use axum::{routing::get, Router};
use lazy_static::lazy_static;
use redb::{Database, TableDefinition};
use rkyv::Deserialize as _;

lazy_static! {
    static ref DB: Database = Database::create("db.redb").expect("failed to open database");
}

const LOG_TABLE: TableDefinition<u64, Trust> = TableDefinition::new("log");

#[tokio::main]
async fn main() {
    let write_txn = DB.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(LOG_TABLE).unwrap();
        table.insert(&12, Trust { from: 1 }).unwrap();
        table.insert(&7, Trust { from: 2 }).unwrap();
        table.insert(&13, Trust { from: 3 }).unwrap();
        table.insert(&1, Trust { from: 4 }).unwrap();
    }
    let _ = write_txn.commit().expect("failed to create log table");

    let app = Router::new()
        .route("/", get(|| async { "cassis" }))
        .route("/log", get(getlog));

    println!("listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn getlog() -> String {
    let txn = DB.begin_read().unwrap();
    let table = txn
        .open_table(LOG_TABLE)
        .expect("failed to open table when reading log");

    let mut res = String::with_capacity(150);
    for row in table.range(0..).expect("failed to open iterator") {
        let (_, v) = row.unwrap();
        res.push_str(format!("{}", v.value().from).as_str());
        res.push_str(",");
    }
    res
}

#[derive(Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
struct Trust {
    from: u32,
}

impl redb::Value for Trust {
    fn type_name() -> redb::TypeName {
        redb::TypeName::new("trust")
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        rkyv::to_bytes::<Trust, 7>(value).expect("failed to serialize")
    }

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let archived = unsafe { rkyv::archived_root::<Trust>(&data[..]) };
        archived
            .deserialize(&mut rkyv::Infallible)
            .expect("failed to deserialize")
    }

    type AsBytes<'a> = rkyv::AlignedVec;
    type SelfType<'a> = Trust;
}
