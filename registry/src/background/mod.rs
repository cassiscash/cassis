use anyhow::anyhow;
use std::{env, path::Path, sync::mpsc, thread};
use tokio::sync::oneshot;

mod db;
mod state;

use db::LogStore;

pub fn start(pk: cassis::PublicKey) -> Requester {
    let (tx, rx) = mpsc::channel::<(oneshot::Sender<Response>, Request)>();

    let _join = thread::spawn(move || {
        let logstore_path = env::var("STORE_PATH").unwrap_or("logstore".to_string());
        let mut ls =
            LogStore::init(&Path::new(&logstore_path)).expect("failed to instantiate logstore");
        ls.check_and_heal()
            .expect("failed to check and heal logstore");

        let mut state = state::init(pk, &ls).expect("failed to initialize state");

        for req in rx {
            let resp = match req.1 {
                Request::AppendOperation(op) => {
                    // validate this operation
                    let _ = match cassis::state::validate(&state, &op) {
                        Err(err) => return Err(err),
                        _ => {}
                    };

                    // once we know it's ok we append it
                    ls.append_operation(&op)
                        .map_or_else(|e| Response::Error(e), |_| Response::OK);

                    // and then we apply the changes
                    cassis::state::process(&mut state, &op);

                    Response::OK
                }
                Request::ListOperations(from, to) => {
                    let iter_res = match (from, to) {
                        (None, None) => ls.range(..50),
                        (Some(from), None) => ls.range(from..from + 50),
                        (None, Some(to)) => ls.range(to - 50..to),
                        (Some(from), Some(to)) => ls.range(from..to),
                    };

                    iter_res
                        .map(|range| {
                            Response::Operations(range.collect::<Vec<cassis::Operation>>())
                        })
                        .map_or_else(|e| Response::Error(e), |_| Response::OK)
                }
                Request::ReadOperation(id) => ls.read_operation(id).map_or_else(
                    |_| Response::Error(anyhow!("not found")),
                    |op| Response::Operation(op),
                ),
                Request::GetKeyID(pubkey) => state.key_indexes.get(&pubkey).map_or_else(
                    || Response::Error(anyhow!("not found")),
                    |idx| Response::KeyIdx(*idx),
                ),
                Request::GetLines => {
                    let mut lines: Vec<cassis::state::Line> = Vec::with_capacity(12);
                    for (_, line) in state.lines.iter() {
                        lines.push(line.clone());
                    }
                    Response::Lines(lines)
                }
            };
            req.0.send(resp).expect("failed to send response back");
        }

        Ok(())
    });

    Requester { sender: tx }
}

#[derive(Debug)]
enum Request {
    AppendOperation(cassis::Operation),
    ListOperations(Option<u32>, Option<u32>),
    GetKeyID([u8; 32]),
    ReadOperation(u32),
    GetLines,
}

#[derive(Debug)]
enum Response {
    OK,
    Operation(cassis::Operation),
    Operations(Vec<cassis::Operation>),
    Lines(Vec<cassis::state::Line>),
    KeyIdx(u32),
    Error(anyhow::Error),
}

pub struct Requester {
    sender: mpsc::Sender<(oneshot::Sender<Response>, Request)>,
}

impl Requester {
    async fn request(&self, req: Request) -> Response {
        let (tx, rx) = oneshot::channel::<Response>();
        self.sender
            .send((tx, req))
            .expect("failed to send message to db thread");
        rx.await.expect("failed to receive state from oneshot")
    }

    pub async fn append_operation(&self, op: cassis::Operation) -> Result<(), anyhow::Error> {
        match self.request(Request::AppendOperation(op)).await {
            Response::OK => Ok(()),
            Response::Error(err) => Err(err),
            _ => panic!("got unexpected response!"),
        }
    }

    pub async fn list(
        &self,
        from: Option<u32>,
        to: Option<u32>,
    ) -> Result<Vec<cassis::Operation>, anyhow::Error> {
        match self.request(Request::ListOperations(from, to)).await {
            Response::Operations(ops) => Ok(ops),
            Response::Error(err) => Err(err),
            _ => panic!("got unexpected response!"),
        }
    }

    pub async fn get_key_id(&self, pubkey: [u8; 32]) -> Option<u32> {
        match self.request(Request::GetKeyID(pubkey)).await {
            Response::KeyIdx(idx) => Some(idx),
            _ => None,
        }
    }

    pub async fn read_operation(&self, id: u32) -> Option<cassis::Operation> {
        match self.request(Request::ReadOperation(id)).await {
            Response::Operation(op) => Some(op),
            _ => None,
        }
    }

    // this is temporary, for debugging purposes
    pub async fn get_lines(&self) -> Vec<cassis::state::Line> {
        match self.request(Request::GetLines).await {
            Response::Lines(lines) => lines,
            _ => vec![],
        }
    }
}
