use ethernet_frame::{EtherType, EthernetFrame};
use ip_protocol::{IPv4, Packet};

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

    for _ in 0.. {
        if let Ok(packet) = cap.next_packet() {
            let eth_frame = EthernetFrame::serialize(&packet);

            let ip_packet: Option<Box<dyn Packet>> = match eth_frame.ip_type {
                EtherType::IPv4 => Some(ip_protocol::IPv4::serialize(&packet, eth_frame)),
                _ => {
                    eprintln!("Unknown {:?}", eth_frame.ip_type.to_string());
                    continue;
                }
            };

            if let Some(ip_packet) = ip_packet {
                let packet_ref: &dyn Packet = &*ip_packet;
                let ipv4_packet: &IPv4 = packet_ref
                    .as_any()
                    .downcast_ref::<IPv4>()
                    .expect("Not IPv4");

                println!("dst mac {}", ipv4_packet.eth_frame.to_string_dest_mac());
                println!("src mac {}", ipv4_packet.eth_frame.to_string_src_mac());
                println!("type {}", ipv4_packet.eth_frame.ip_type.to_string());
                println!("version {}", ipv4_packet.version);
                println!("ihc {}", ipv4_packet.ihl);
                println!("dscp {}", ipv4_packet.dscp);
                println!("ecn {}", ipv4_packet.ecn);
                println!("total length {}", ipv4_packet.total_length);
                println!("identification {}", ipv4_packet.identification);
                println!("flags {}", ipv4_packet.flags);
                println!("fragment offset {}", ipv4_packet.fragment_offset);
                println!("time to live {}", ipv4_packet.time_to_live);
                println!("protocol {}", ipv4_packet.protocol);
                println!("header checksum {}", ipv4_packet.header_checksum);
                println!("src addr {}", ipv4_packet.to_string_src_addr());
                println!("dst addr {}", ipv4_packet.to_string_dst_addr());
                println!("options len {}", ipv4_packet.options.len());
                println!("data len {}", ipv4_packet.data.len());
            } else {
                eprintln!("No valid IP packet found!");
            }
        }
    }
}
