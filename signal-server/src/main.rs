use std::net::{TcpListener, TcpStream};

fn handle_connection(stream: TcpStream) {
    println!("Client: {}", stream.peer_addr().unwrap());
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    println!("Server listening on {}", listener.local_addr().unwrap());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_connection(stream),
            Err(e) => println!("Error: {}", e)
        }
    }

    Ok(())
}
