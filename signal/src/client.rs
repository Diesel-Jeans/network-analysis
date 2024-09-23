use proto::greeter_client::GreeterClient;
use tonic::transport::{Channel, Certificate, ClientTlsConfig, Identity};

pub mod proto {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://127.0.0.1:8080";

    // let pem = std::fs::read_to_string("./tls/client.key")?;
    // let ca = Certificate::from_pem(pem);

    // let cert = std::fs::read_to_string("./tls/client.crt")?;
    // let key = std::fs::read_to_string("./tls/client.key")?;
    // let identity = Identity::from_pem(cert, key);

    // Load the root CA certificate
    let ca_cert = std::fs::read_to_string("./tls/ca.pem")?;
    let ca = Certificate::from_pem(ca_cert);

    let tls = ClientTlsConfig::new()
        //.identity(identity)
        .ca_certificate(ca)
        .domain_name("localhost");

    let channel = Channel::from_static(url)
    .tls_config(tls)?
    .connect()
    .await?;

    println!("Client!");

    let mut client = GreeterClient::new(channel);

    let req = proto::HelloRequest {
        name: "Client Eastwood".to_string()
    };
    
    let request = tonic::Request::new(req);
    let response = client.say_hello(request).await?;
    
    println!("Response: {:?}", response.get_ref().message);
    
    Ok(())
}