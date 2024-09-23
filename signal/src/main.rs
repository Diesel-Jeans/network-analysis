use proto::{greeter_server::{Greeter, GreeterServer}, HelloReply, HelloRequest};
use tonic::{
    transport::{
        server::{TcpConnectInfo, TlsConnectInfo},
        Identity, Server, ServerTlsConfig, Certificate
    },
    Request, Response, Status,
};

mod proto {
    tonic::include_proto!("helloworld");
}

#[derive(Debug, Default)]
pub struct GreeterService {}

#[tonic::async_trait]
impl Greeter for GreeterService {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {

        // let conn_info = request
        //     .extensions()
        //     .get::<TlsConnectInfo<TcpConnectInfo>>()
        //     .unwrap();

        println!("Request from client: {:?} with info", request.remote_addr());

        let reply = HelloReply {
            message: format!("Server says hello {}!", request.into_inner().name),
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = std::fs::read_to_string("./tls/server.pem")?;
    let key = std::fs::read_to_string("./tls/server.key")?;

    println!("cert {}", cert);
    println!("key {}", key);

    let identity = Identity::from_pem(cert, key);
    //println!("identity {:?}", identity);

    let ca_cert = std::fs::read_to_string("./tls/ca.pem")?;
    let ca = Certificate::from_pem(ca_cert);
    println!("ca {:?}", ca);
    
    let addr = "127.0.0.1:8080".parse()?;
    let greeter = GreeterService::default();

    Server::builder()
        .tls_config(ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(ca)
        )?
        .add_service(GreeterServer::new(greeter))
        .serve(addr)
        .await?;
    
    Ok(())
}