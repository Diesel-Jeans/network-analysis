use ethernet_frame::{EtherType, EthernetFrame};
use ip_protocol::Packet;

mod ethernet_frame;
mod ip_protocol;

fn main() {
    let device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    let mut cap = pcap::Capture::from_device("wlp0s20f3")
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    for _ in 0..1 {
        if let Ok(packet) = cap.next_packet() {
            let eth_frame = EthernetFrame::create(&packet);

            let ip_packet: Box<dyn Packet> = match eth_frame.ip_type {
                EtherType::IPv4 => ip_protocol::IPv4::create(&packet, &eth_frame),
                EtherType::IPv6 => ip_protocol::IPv6::create(&packet, &eth_frame),
                _ => {
                    eprintln!("Unknown IP protocol: {:?}", eth_frame.ip_type.to_string());
                    continue;
                }
            };

            println!("ip type: {}", ip_packet.get_eth_frame().to_string_ip_type());
            println!("src MAC: {}", ip_packet.get_eth_frame().to_string_src_mac());
            println!("dest MAC: {}", ip_packet.get_eth_frame().to_string_dest_mac());
            println!("src addr: {}", ip_packet.src_addr());
            println!("dest addr: {}", ip_packet.dest_addr());
        }
    }
}
