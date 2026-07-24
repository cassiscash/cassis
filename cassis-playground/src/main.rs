#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cassis_playground::run().await
}
