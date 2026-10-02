//! Usage: outbound-client tcp/127.0.0.1:7447 [local] [one]
use zenss_client_sdk::{Client, ClientOptions};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or("tcp/127.0.0.1:7447".into());
    let deployment = args.next().unwrap_or("local".into());
    let instance = args.next().unwrap_or("one".into());
    zenss_client_sdk::ServiceIdentity::new(&deployment, "echo", &instance)?;
    let client = Client::connect(ClientOptions {
        endpoints: vec![endpoint],
        tls: None,
        timeout_ms: 5000,
    })
    .await?;
    let response = client
        .query(
            &format!("zenss/v1/{deployment}/products/echo/{instance}/query"),
            b"hello from outbound SDK".to_vec(),
        )
        .await?;
    let result: serde_json::Value = serde_json::from_slice(&response)?;
    println!("{result}");
    client.close().await?;
    Ok(())
}
