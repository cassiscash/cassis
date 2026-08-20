package main

// Runs arkd-wallet inside the arkd process, backed by Esplora (see
// esplora.go), and points arkd at it.
//
// Configured with the regular arkd-wallet variables, all optional:
//
//	ARKD_WALLET_NETWORK  bitcoin, testnet, signet, mutinynet or regtest (default mutinynet)
//	ARKD_WALLET_DATADIR  wallet data (default $ARKD_DATADIR/wallet)
//	ARKD_WALLET_PORT     wallet gRPC port (default: a free one)
//	ARKD_WALLET_SIGNER_KEY
//
// and ARKD_ESPLORA_URL, shared with arkd.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"encoding/hex"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/config"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application/scanner"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application/wallet"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/infrastructure/cypher"
	db "github.com/arkade-os/arkd/pkg/arkd-wallet/core/infrastructure/db/badger"
	walletgrpc "github.com/arkade-os/arkd/pkg/arkd-wallet/interface/grpc"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
)

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func networkByName(name string) (arklib.Network, error) {
	for _, network := range []arklib.Network{
		arklib.Bitcoin, arklib.BitcoinTestNet, arklib.BitcoinSigNet,
		arklib.BitcoinMutinyNet, arklib.BitcoinRegTest,
	} {
		if strings.EqualFold(network.Name, name) {
			return network, nil
		}
	}
	return arklib.Network{}, fmt.Errorf("unknown network %q", name)
}

func freePort() (uint32, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return uint32(listener.Addr().(*net.TCPAddr).Port), nil
}

// Start the wallet and set ARKD_WALLET_ADDR to it. Must run before
// arkd loads its config, which connects to the wallet.
func startEmbeddedWallet() error {
	network, err := networkByName(env("ARKD_WALLET_NETWORK", arklib.BitcoinMutinyNet.Name))
	if err != nil {
		return err
	}
	esploraURL := os.Getenv("ARKD_ESPLORA_URL")
	if esploraURL == "" {
		return fmt.Errorf("ARKD_ESPLORA_URL is required")
	}
	datadir := env("ARKD_WALLET_DATADIR", filepath.Join(env("ARKD_DATADIR", arklib.AppDataDir("arkd", false)), "wallet"))
	dbDir := filepath.Join(datadir, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return err
	}
	var port uint32
	if raw := os.Getenv("ARKD_WALLET_PORT"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return fmt.Errorf("ARKD_WALLET_PORT: %w", err)
		}
		port = uint32(parsed)
	} else if port, err = freePort(); err != nil {
		return err
	}
	var signerKey *btcec.PrivateKey
	if raw := os.Getenv("ARKD_WALLET_SIGNER_KEY"); raw != "" {
		buf, err := hex.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("ARKD_WALLET_SIGNER_KEY must be hex")
		}
		signerKey, _ = btcec.PrivKeyFromBytes(buf)
	}

	chain, err := newEsplora(esploraURL, application.NetworkToChainParams(network.Name), filepath.Join(datadir, "addresses.json"))
	if err != nil {
		return err
	}
	seeds, err := db.NewSeedRepository(dbDir, nil)
	if err != nil {
		return fmt.Errorf("wallet seed repository: %w", err)
	}
	scannerSvc, err := scanner.New(chain, network.Name)
	if err != nil {
		return fmt.Errorf("wallet scanner: %w", err)
	}
	cfg := &config.Config{
		Port:     port,
		DbDir:    dbDir,
		LogLevel: int(log.GetLevel()),
		Network:  network,
		WalletSvc: wallet.New(wallet.WalletOptions{
			SeedRepository: seeds,
			Cypher:         cypher.New(),
			Nbxplorer:      chain,
			Network:        network.Name,
			SignerKey:      signerKey,
		}),
		ScannerSvc: scannerSvc,
	}
	svc, err := walletgrpc.NewService(cfg)
	if err != nil {
		return fmt.Errorf("wallet service: %w", err)
	}
	if err := svc.Start(); err != nil {
		return fmt.Errorf("start wallet service: %w", err)
	}
	log.RegisterExitHandler(svc.Stop)
	log.Infof("embedded wallet (%s, esplora %s) listens on 127.0.0.1:%d", network.Name, esploraURL, port)
	return os.Setenv("ARKD_WALLET_ADDR", fmt.Sprintf("127.0.0.1:%d", port))
}
