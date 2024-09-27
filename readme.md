# Run with Docker
1. Set your network interface in `.env`
2. Run with docker compose
```bash
sudo docker compose up --build
```

### (Optional)
Connect host machine to containers. Will reset on reboot.
```bash
sudo ./host_to_container_bridge.sh
nmap 192.168.87.0/24 
```

# Run local testing
1. Set your host IP in `.env`
2. Run server and client
```bash
cargo run --bin server
cargo run --bin client
```

```bash
cargo build && \
    sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/analysis && \
    ./target/debug/analysis
```

# Run Analysis
1. Follow installing dependencies for [pcap](https://github.com/rust-pcap/pcap)
```bash
# Run on linux
cargo build -p analysis && \
    sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/analysis && \
    ./target/debug/analysis
```