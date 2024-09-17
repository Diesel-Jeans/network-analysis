use std::net::TcpStream;

fn main() {
    if let Ok(stream) = TcpStream::connect("192.168.87.65:8080") {
        println!("Connected to the server: {}", stream.peer_addr().unwrap());
    } else {
        println!("Couldn't connect to server...");
    }
}
