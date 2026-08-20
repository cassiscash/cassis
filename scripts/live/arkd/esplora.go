package main

// An Esplora-backed implementation of arkd-wallet's `ports.Nbxplorer`,
// so the operator wallet needs no NBXplorer (and no bitcoind) of its
// own: everything goes through a public Esplora REST API.
//
// Derivation schemes are NBXplorer's taproot ones, "<xpub>-[taproot]",
// with BIP86 key-path-only addresses at <xpub>/<chain>/<index>
// (chain 0 deposits, 1 change). Address usage is tracked in a small
// JSON file so the wallet resumes where it left off; a restore does a
// gap-limit scan instead.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/ports"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
)

const (
	// Unused addresses looked at past the last used or issued one.
	addressGap = 5
	// Gap limit of the scan done when restoring a wallet.
	restoreGap = 20
	// 1 sat/vB plus a 10% margin, as the NBXplorer backend does.
	minRelayTxFee = chainfee.SatPerKVByte(1100)
	// Watched addresses are polled this often for new outputs.
	watchInterval = 5 * time.Second
	// Concurrent Esplora requests per address sweep.
	maxParallelRequests = 8
)

// Usage of one account (derivation scheme), persisted.
type accountState struct {
	// Per chain: indices that received coins at some point.
	Used [2]map[uint32]bool `json:"used"`
	// Per chain: indices that received and no longer hold any coin.
	// The wallet never hands them out again, so they are not polled.
	Dead [2]map[uint32]bool `json:"dead"`
	// Per chain: one past the highest index handed out.
	Issued [2]uint32 `json:"issued"`
}

type account struct {
	xpub  *hdkeychain.ExtendedKey
	state *accountState
	// Per chain: derived addresses by index.
	addresses [2][]derivedAddress
}

type derivedAddress struct {
	address string
	script  string
}

type esplora struct {
	url       string
	http      *http.Client
	params    *chaincfg.Params
	statePath string

	lock     sync.Mutex
	accounts map[string]*account
	// Watched address -> outpoints already reported (or present when
	// the watch started).
	watched map[string]map[wire.OutPoint]bool
}

func newEsplora(url string, params *chaincfg.Params, statePath string) (*esplora, error) {
	e := &esplora{
		url:       strings.TrimSuffix(url, "/"),
		http:      &http.Client{Timeout: 30 * time.Second},
		params:    params,
		statePath: statePath,
		accounts:  map[string]*account{},
		watched:   map[string]map[wire.OutPoint]bool{},
	}
	if _, err := e.GetBitcoinStatus(context.Background()); err != nil {
		return nil, fmt.Errorf("esplora %s: %w", e.url, err)
	}
	return e, nil
}

// --- HTTP ---

var errNotFound = errors.New("not found")

func (e *esplora) request(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, e.url+path, body)
	if err != nil {
		return nil, err
	}
	var data []byte
	for attempt := 0; ; attempt++ {
		resp, err := e.http.Do(req)
		if err != nil {
			return nil, err
		}
		data, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return data, nil
		case resp.StatusCode == http.StatusNotFound:
			return nil, errNotFound
		// Public instances rate limit; back off a little.
		case resp.StatusCode == http.StatusTooManyRequests && attempt < 5 && body == nil:
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
}

func (e *esplora) getJSON(ctx context.Context, path string, out any) error {
	data, err := e.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (e *esplora) tipHeight(ctx context.Context) (uint32, error) {
	data, err := e.request(ctx, http.MethodGet, "/blocks/tip/height", nil)
	if err != nil {
		return 0, err
	}
	height, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	return uint32(height), err
}

type txStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHeight uint32 `json:"block_height"`
	BlockTime   int64  `json:"block_time"`
}

func confirmations(status txStatus, tip uint32) uint32 {
	if !status.Confirmed || status.BlockHeight > tip {
		return 0
	}
	return tip - status.BlockHeight + 1
}

type esploraUtxo struct {
	Txid   string   `json:"txid"`
	Vout   uint32   `json:"vout"`
	Value  uint64   `json:"value"`
	Status txStatus `json:"status"`
}

// Unspent outputs at `addr`, mempool included.
func (e *esplora) addressUtxos(ctx context.Context, addr string) ([]esploraUtxo, error) {
	var utxos []esploraUtxo
	err := e.getJSON(ctx, "/address/"+addr+"/utxo", &utxos)
	return utxos, err
}

// Whether `addr` ever received anything, mempool included.
func (e *esplora) addressUsed(ctx context.Context, addr string) (bool, error) {
	var stats struct {
		Chain struct {
			TxCount int `json:"tx_count"`
		} `json:"chain_stats"`
		Mempool struct {
			TxCount int `json:"tx_count"`
		} `json:"mempool_stats"`
	}
	if err := e.getJSON(ctx, "/address/"+addr, &stats); err != nil {
		return false, err
	}
	return stats.Chain.TxCount+stats.Mempool.TxCount > 0, nil
}

// Run `f` over `n` items with bounded parallelism; the first error wins.
func parallel(n int, f func(i int) error) error {
	var (
		wg       sync.WaitGroup
		once     sync.Once
		firstErr error
		slots    = make(chan struct{}, maxParallelRequests)
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		slots <- struct{}{}
		go func(i int) {
			defer func() { <-slots; wg.Done() }()
			if err := f(i); err != nil {
				once.Do(func() { firstErr = err })
			}
		}(i)
	}
	wg.Wait()
	return firstErr
}

// --- accounts ---

func newAccountState() *accountState {
	s := &accountState{}
	for chain := range 2 {
		s.Used[chain] = map[uint32]bool{}
		s.Dead[chain] = map[uint32]bool{}
	}
	return s
}

func (e *esplora) loadStates() map[string]*accountState {
	states := map[string]*accountState{}
	data, err := os.ReadFile(e.statePath)
	if err != nil {
		return states
	}
	if err := json.Unmarshal(data, &states); err != nil {
		log.Warnf("ignoring unreadable wallet state %s: %s", e.statePath, err)
		return map[string]*accountState{}
	}
	for _, s := range states {
		for chain := range 2 {
			if s.Used[chain] == nil {
				s.Used[chain] = map[uint32]bool{}
			}
			if s.Dead[chain] == nil {
				s.Dead[chain] = map[uint32]bool{}
			}
		}
	}
	return states
}

// Persist account usage. Called with the lock held.
func (e *esplora) saveStates() {
	states := map[string]*accountState{}
	for scheme, acc := range e.accounts {
		states[scheme] = acc.state
	}
	data, err := json.Marshal(states)
	if err == nil {
		err = os.WriteFile(e.statePath, data, 0o600)
	}
	if err != nil {
		log.Errorf("failed to save wallet state: %s", err)
	}
}

// The account of `scheme`, loading its persisted usage on first use.
// Called with the lock held.
func (e *esplora) account(scheme string) (*account, error) {
	if acc, ok := e.accounts[scheme]; ok {
		return acc, nil
	}
	xpubStr, ok := strings.CutSuffix(scheme, "-[taproot]")
	if !ok {
		return nil, fmt.Errorf("unsupported derivation scheme %q: only taproot ones are", scheme)
	}
	xpub, err := hdkeychain.NewKeyFromString(xpubStr)
	if err != nil {
		return nil, fmt.Errorf("invalid derivation scheme: %w", err)
	}
	state := e.loadStates()[scheme]
	if state == nil {
		state = newAccountState()
	}
	acc := &account{xpub: xpub, state: state}
	e.accounts[scheme] = acc
	return acc, nil
}

// Address at chain/index, deriving it if needed. Called with the lock held.
func (e *esplora) addressAt(acc *account, chain int, index uint32) (derivedAddress, error) {
	for uint32(len(acc.addresses[chain])) <= index {
		next := uint32(len(acc.addresses[chain]))
		branch, err := acc.xpub.Derive(uint32(chain))
		if err != nil {
			return derivedAddress{}, err
		}
		child, err := branch.Derive(next)
		if err != nil {
			return derivedAddress{}, err
		}
		pubkey, err := child.ECPubKey()
		if err != nil {
			return derivedAddress{}, err
		}
		outputKey := txscript.ComputeTaprootKeyNoScript(pubkey)
		addr, err := address.NewAddressTaproot(schnorr.SerializePubKey(outputKey), e.params)
		if err != nil {
			return derivedAddress{}, err
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return derivedAddress{}, err
		}
		acc.addresses[chain] = append(acc.addresses[chain], derivedAddress{
			address: addr.EncodeAddress(),
			script:  hex.EncodeToString(script),
		})
	}
	return acc.addresses[chain][index], nil
}

// One past the highest index that may hold coins: used or issued.
func (s *accountState) frontier(chain int) uint32 {
	frontier := s.Issued[chain]
	for index := range s.Used[chain] {
		frontier = max(frontier, index+1)
	}
	return frontier
}

type slot struct {
	chain int
	index uint32
	derivedAddress
}

// Addresses of `scheme` that may hold coins, plus `gap` fresh ones per
// chain.
func (e *esplora) liveAddresses(scheme string, gap uint32) (*account, []slot, error) {
	e.lock.Lock()
	defer e.lock.Unlock()
	acc, err := e.account(scheme)
	if err != nil {
		return nil, nil, err
	}
	var slots []slot
	for chain := range 2 {
		for index := uint32(0); index < acc.state.frontier(chain)+gap; index++ {
			if acc.state.Dead[chain][index] {
				continue
			}
			addr, err := e.addressAt(acc, chain, index)
			if err != nil {
				return nil, nil, err
			}
			slots = append(slots, slot{chain, index, addr})
		}
	}
	return acc, slots, nil
}

// --- ports.Nbxplorer ---

func (e *esplora) GetBitcoinStatus(ctx context.Context) (*ports.BitcoinStatus, error) {
	data, err := e.request(ctx, http.MethodGet, "/blocks/tip/hash", nil)
	if err != nil {
		return nil, err
	}
	var block struct {
		Height     uint32 `json:"height"`
		MedianTime int64  `json:"mediantime"`
	}
	if err := e.getJSON(ctx, "/block/"+strings.TrimSpace(string(data)), &block); err != nil {
		return nil, err
	}
	return &ports.BitcoinStatus{
		ChainTipHeight: block.Height,
		ChainTipTime:   block.MedianTime,
		Synced:         true,
		MinRelayTxFee:  minRelayTxFee,
	}, nil
}

func (e *esplora) GetTransaction(ctx context.Context, txid string) (*ports.TransactionDetails, error) {
	if _, err := chainhash.NewHashFromStr(txid); err != nil {
		return nil, fmt.Errorf("invalid txid: %w", err)
	}
	raw, err := e.request(ctx, http.MethodGet, "/tx/"+txid+"/hex", nil)
	if errors.Is(err, errNotFound) {
		return nil, application.ErrTransactionNotFound
	}
	if err != nil {
		return nil, err
	}
	var status txStatus
	if err := e.getJSON(ctx, "/tx/"+txid+"/status", &status); err != nil {
		return nil, err
	}
	tip, err := e.tipHeight(ctx)
	if err != nil {
		return nil, err
	}
	timestamp := status.BlockTime
	if !status.Confirmed {
		timestamp = time.Now().Unix()
	}
	return &ports.TransactionDetails{
		TxID:          txid,
		Hex:           strings.TrimSpace(string(raw)),
		Height:        status.BlockHeight,
		Timestamp:     timestamp,
		Confirmations: confirmations(status, tip),
	}, nil
}

// Gap-limit scan for a restored wallet: marks every address that ever
// received anything as used.
func (e *esplora) ScanUtxoSet(ctx context.Context, scheme string, _ int) <-chan ports.ScanUtxoSetProgress {
	progress := make(chan ports.ScanUtxoSetProgress, 1)
	go func() {
		defer close(progress)
		if err := e.scan(ctx, scheme); err != nil {
			log.Errorf("wallet scan of %s failed: %s", scheme, err)
		}
		progress <- ports.ScanUtxoSetProgress{Progress: 100, Done: true}
	}()
	return progress
}

func (e *esplora) scan(ctx context.Context, scheme string) error {
	for chain := range 2 {
		unused := 0
		for index := uint32(0); unused < restoreGap; index++ {
			e.lock.Lock()
			acc, err := e.account(scheme)
			var addr derivedAddress
			if err == nil {
				addr, err = e.addressAt(acc, chain, index)
			}
			e.lock.Unlock()
			if err != nil {
				return err
			}
			used, err := e.addressUsed(ctx, addr.address)
			if err != nil {
				return err
			}
			if !used {
				unused++
				continue
			}
			unused = 0
			e.lock.Lock()
			acc.state.Used[chain][index] = true
			e.lock.Unlock()
		}
	}
	e.lock.Lock()
	e.saveStates()
	e.lock.Unlock()
	return nil
}

func (e *esplora) Track(_ context.Context, scheme string) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	_, err := e.account(scheme)
	return err
}

func (e *esplora) GetUtxos(ctx context.Context, scheme string) ([]ports.Utxo, error) {
	acc, slots, err := e.liveAddresses(scheme, addressGap)
	if err != nil {
		return nil, err
	}
	tip, err := e.tipHeight(ctx)
	if err != nil {
		return nil, err
	}
	found := make([][]esploraUtxo, len(slots))
	if err := parallel(len(slots), func(i int) error {
		utxos, err := e.addressUtxos(ctx, slots[i].address)
		found[i] = utxos
		return err
	}); err != nil {
		return nil, err
	}

	e.lock.Lock()
	defer e.lock.Unlock()
	var result []ports.Utxo
	changed := false
	for i, s := range slots {
		state := acc.state
		if len(found[i]) == 0 {
			// Emptied: it held coins before, so it is spent for good.
			if state.Used[s.chain][s.index] && !state.Dead[s.chain][s.index] {
				state.Dead[s.chain][s.index] = true
				changed = true
			}
			continue
		}
		if !state.Used[s.chain][s.index] {
			state.Used[s.chain][s.index] = true
			changed = true
		}
		for _, u := range found[i] {
			hash, err := chainhash.NewHashFromStr(u.Txid)
			if err != nil {
				return nil, err
			}
			result = append(result, ports.Utxo{
				OutPoint:      wire.OutPoint{Hash: *hash, Index: u.Vout},
				Value:         u.Value,
				Script:        s.script,
				Address:       s.address,
				Confirmations: confirmations(u.Status, tip),
			})
		}
	}
	if changed {
		e.saveStates()
	}
	return result, nil
}

func (e *esplora) GetScriptPubKeyDetails(_ context.Context, scheme string, script string) (*ports.ScriptPubKeyDetails, error) {
	_, slots, err := e.liveAddresses(scheme, addressGap)
	if err != nil {
		return nil, err
	}
	for _, s := range slots {
		if s.script == script {
			return &ports.ScriptPubKeyDetails{KeyPath: fmt.Sprintf("%d/%d", s.chain, s.index)}, nil
		}
	}
	return nil, fmt.Errorf("script %s does not belong to %s", script, scheme)
}

// The `skip`-th address that never received anything and was not
// handed out before on the deposit or change chain.
func (e *esplora) GetNewUnusedAddress(ctx context.Context, scheme string, change bool, skip int) (string, error) {
	chain := 0
	if change {
		chain = 1
	}
	for index := uint32(0); ; index++ {
		e.lock.Lock()
		acc, err := e.account(scheme)
		var addr derivedAddress
		if err == nil {
			addr, err = e.addressAt(acc, chain, index)
		}
		known := err == nil && acc.state.Used[chain][index]
		e.lock.Unlock()
		if err != nil {
			return "", err
		}
		if known {
			continue
		}
		used, err := e.addressUsed(ctx, addr.address)
		if err != nil {
			return "", err
		}
		e.lock.Lock()
		if used {
			acc.state.Used[chain][index] = true
		} else if skip == 0 {
			acc.state.Issued[chain] = max(acc.state.Issued[chain], index+1)
		}
		e.saveStates()
		e.lock.Unlock()
		if used {
			continue
		}
		if skip == 0 {
			return addr.address, nil
		}
		skip--
	}
}

func (e *esplora) EstimateFeeRate(ctx context.Context) (chainfee.SatPerKVByte, error) {
	var estimates map[string]float64
	if err := e.getJSON(ctx, "/fee-estimates", &estimates); err != nil {
		return 0, err
	}
	satPerVByte, ok := estimates["1"]
	if !ok {
		return minRelayTxFee, nil
	}
	return max(chainfee.SatPerKVByte(satPerVByte*1000), minRelayTxFee), nil
}

// One transaction, or a parent and its child as a package (falling
// back to broadcasting them in order where packages are unsupported).
func (e *esplora) BroadcastTransaction(ctx context.Context, txs ...string) (string, error) {
	switch len(txs) {
	case 1:
		data, err := e.request(ctx, http.MethodPost, "/tx", strings.NewReader(txs[0]))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	case 2:
		body, _ := json.Marshal(txs)
		data, err := e.request(ctx, http.MethodPost, "/txs/package", bytes.NewReader(body))
		if err == nil {
			return string(data), nil
		}
		log.Debugf("package broadcast failed (%s), broadcasting in order", err)
		var txids []string
		for _, tx := range txs {
			txid, err := e.BroadcastTransaction(ctx, tx)
			if err != nil {
				return "", err
			}
			txids = append(txids, txid)
		}
		return strings.Join(txids, ","), nil
	default:
		return "", fmt.Errorf("unsupported transaction count: %d (only 1 or 2)", len(txs))
	}
}

// Esplora always has the full UTXO set; nothing to rescan.
func (e *esplora) RescanUtxos(context.Context, []wire.OutPoint) error {
	return nil
}

func (e *esplora) IsSpent(ctx context.Context, outpoint wire.OutPoint) (bool, error) {
	var outspend struct {
		Spent bool `json:"spent"`
	}
	path := fmt.Sprintf("/tx/%s/outspend/%d", outpoint.Hash, outpoint.Index)
	if err := e.getJSON(ctx, path, &outspend); err != nil {
		return false, err
	}
	return outspend.Spent, nil
}

// Watch `addresses` for new outputs; those already there are not
// reported.
func (e *esplora) WatchAddresses(ctx context.Context, addresses ...string) error {
	if len(addresses) == 0 {
		return fmt.Errorf("no addresses provided")
	}
	for _, addr := range addresses {
		utxos, err := e.addressUtxos(ctx, addr)
		if err != nil {
			return err
		}
		seen := map[wire.OutPoint]bool{}
		for _, u := range utxos {
			if hash, err := chainhash.NewHashFromStr(u.Txid); err == nil {
				seen[wire.OutPoint{Hash: *hash, Index: u.Vout}] = true
			}
		}
		e.lock.Lock()
		if _, ok := e.watched[addr]; !ok {
			e.watched[addr] = seen
		}
		e.lock.Unlock()
	}
	return nil
}

func (e *esplora) UnwatchAddresses(_ context.Context, addresses ...string) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	for _, addr := range addresses {
		delete(e.watched, addr)
	}
	return nil
}

// New outputs at watched addresses, polled every `watchInterval`.
func (e *esplora) GetAddressNotifications(ctx context.Context) (<-chan []ports.Utxo, error) {
	notifications := make(chan []ports.Utxo, 64)
	go func() {
		defer close(notifications)
		ticker := time.NewTicker(watchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			for _, batch := range e.pollWatched(ctx) {
				select {
				case notifications <- batch:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return notifications, nil
}

// Outputs that appeared at watched addresses since the last poll,
// grouped by transaction.
func (e *esplora) pollWatched(ctx context.Context) [][]ports.Utxo {
	e.lock.Lock()
	addresses := make([]string, 0, len(e.watched))
	for addr := range e.watched {
		addresses = append(addresses, addr)
	}
	e.lock.Unlock()
	if len(addresses) == 0 {
		return nil
	}
	tip, err := e.tipHeight(ctx)
	if err != nil {
		log.Debugf("watch poll: %s", err)
		return nil
	}
	found := make([][]esploraUtxo, len(addresses))
	_ = parallel(len(addresses), func(i int) error {
		utxos, err := e.addressUtxos(ctx, addresses[i])
		if err != nil {
			log.Debugf("watch poll %s: %s", addresses[i], err)
		}
		found[i] = utxos
		return nil
	})

	e.lock.Lock()
	defer e.lock.Unlock()
	byTx := map[chainhash.Hash][]ports.Utxo{}
	for i, addr := range addresses {
		seen, ok := e.watched[addr]
		if !ok {
			continue
		}
		decoded, err := address.DecodeAddress(addr, e.params)
		if err != nil {
			continue
		}
		script, err := txscript.PayToAddrScript(decoded)
		if err != nil {
			continue
		}
		for _, u := range found[i] {
			hash, err := chainhash.NewHashFromStr(u.Txid)
			if err != nil {
				continue
			}
			outpoint := wire.OutPoint{Hash: *hash, Index: u.Vout}
			if seen[outpoint] {
				continue
			}
			seen[outpoint] = true
			byTx[*hash] = append(byTx[*hash], ports.Utxo{
				OutPoint:      outpoint,
				Value:         u.Value,
				Script:        hex.EncodeToString(script),
				Address:       addr,
				Confirmations: confirmations(u.Status, tip),
			})
		}
	}
	batches := make([][]ports.Utxo, 0, len(byTx))
	for _, utxos := range byTx {
		batches = append(batches, utxos)
	}
	return batches
}

func (e *esplora) Close() error {
	return nil
}
