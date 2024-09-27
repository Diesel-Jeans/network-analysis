mod ethernet_frame;
mod ip_protocol;

fn main() {
     let device = pcap::Device::lookup()
     .expect("device lookup failed")
     .expect("no device available");
    println!("Using device {}", device.name);

    let mut cap = pcap::Capture::from_device(device)
     .unwrap()
     .immediate_mode(true)
     .open()
     .unwrap();

    for _ in 0..1 {
        let mut ethernet_frame: ethernet_frame::EthernetFrame = Default::default();
        let mut ipv4: ip_protocol::IPv4 = Default::default();

        let mut ipv6: ip_protocol::IPv6 = Default::default();

        if let Ok(packet) = cap.next_packet() {
            ethernet_frame.dest_mac = [packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]];
            ethernet_frame.src_mac = [packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]];
            ethernet_frame.ip_type = u16::from_be_bytes([packet[12], packet[13]]);
            ipv4.src_addr = [packet[30], packet[31], packet[32], packet[33]];
            ipv4.dest_addr = [packet[34], packet[35], packet[36], packet[37]];
        }

        println!("dest MAC: {}", ethernet_frame.to_string_dest_mac());
        println!("src MAC: {}", ethernet_frame.to_string_src_mac());
        println!("ip type: {}", ethernet_frame.to_string_ip_type());
        println!("src addr: {}", ip_protocol::ToString::src_addr(&ipv4));
        println!("dest addr: {}", ip_protocol::ToString::dest_addr(&ipv4));

        println!("IPv6: {}", ip_protocol::ToString::dest_addr(&ipv6));
    }
}
