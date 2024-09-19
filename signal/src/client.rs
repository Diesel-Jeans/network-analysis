use proto::greeter_client::GreeterClient;

pub mod proto {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "http://192.168.87.65:8080";
    let mut client = GreeterClient::connect(url).await?;

    let req = proto::HelloRequest {
        name: "Client Eastwood".to_string()
    };

    let request = tonic::Request::new(req);

    let response = client.say_hello(request).await?;

    println!("Response: {:?}", response.get_ref().message);
    
    Ok(())
}