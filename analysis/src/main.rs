use ethernet_frame::{EtherType, EthernetFrame};
use ip_protocol::{IPv4, Packet};

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

    while let Ok(packet) = cap.next_packet() {
        let eth_frame = EthernetFrame::serialize(&packet);

        let ip_packet: Option<Box<dyn Packet>> = match eth_frame.ip_type {
            EtherType::IPv4 => Some(ip_protocol::IPv4::serialize(&packet, eth_frame)),
            _ => {
                eprintln!("Unknown {:?}", eth_frame.ip_type.to_string());
                continue;
            }
        };

        // TODO: Insert into database
        if let Some(packet) = ip_packet {
            println!("dst mac {}", packet.get_eth_frame().to_string_dest_mac());
            println!("src mac {}", packet.get_eth_frame().to_string_src_mac());
            println!("type {}", packet.get_eth_frame().ip_type.to_string());
            println!("ts {:?}", packet.get_time_stamp());

            // Downcast to access members (not nessary in 'production')
            let packet_ref: &dyn Packet = &*packet;
            let ipv4_packet: &IPv4 = packet_ref
                .as_any()
                .downcast_ref::<IPv4>()
                .expect("Not IPv4");

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
            println!("data len {}\n", ipv4_packet.data.len());
        } else {
            eprintln!("No valid IP packet found!");
        }
    }
}
