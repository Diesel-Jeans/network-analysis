use proto::{greeter_client::GreeterClient, HelloRequest};
use tonic::{body::BoxBody, Request};
use hyper::{client::connect::HttpConnector, Client, Uri};
use hyper_openssl::HttpsConnector;
use openssl::{
    ssl::{SslConnector, SslMethod},
    x509::X509,
};

pub mod proto {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the root CA certificate
    let pem = tokio::fs::read("./tls/rootCA.crt").await?;
    let ca = X509::from_pem(&pem[..])?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.cert_store_mut().add_cert(ca)?;
    connector.set_alpn_protos(b"\x02h2")?;

    // Setup HTTPS
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let mut https = HttpsConnector::with_connector(http, connector)?;

    https.set_callback(|c, _| {
        c.set_verify_hostname(false);
        Ok(())
    });

    let hyper = Client::builder().http2_only(true).build(https);

    // Setup client
    let uri = Uri::from_static("https://192.168.87.65:8080");

    let add_origin = tower::service_fn(|mut req: hyper::Request<BoxBody>| {
        let uri = Uri::builder()
            .scheme(uri.scheme().unwrap().clone())
            .authority(uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();

        *req.uri_mut() = uri;

        hyper.request(req)
    });

    let mut client = GreeterClient::new(add_origin);

    let req = Request::new(HelloRequest {
        name: "Client Eastwood".to_string()
    });

    let response = client.say_hello(req).await?;
    
    println!("Response: {:?}", response.get_ref().message);
    
    Ok(())
}