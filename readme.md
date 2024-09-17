# Run
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

