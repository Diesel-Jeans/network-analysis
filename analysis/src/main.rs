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

    for _ in 0..1 {
        if let Ok(packet) = cap.next_packet() {
            let eth_frame = EthernetFrame::serialize(&packet);

            let ip_packet: Box<dyn Packet> = match eth_frame.ip_type {
                EtherType::IPv4 => ip_protocol::IPv4::serialize(&packet, eth_frame),
                EtherType::IPv6 => ip_protocol::IPv6::serialize(&packet, eth_frame),
                _ => {
                    eprintln!("Unknown IP protocol: {:?}", eth_frame.ip_type.to_string());
                    continue;
                }
            };

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

            // if let Some(ipv4_packet) = ip_packet.as_any().downcast_ref::<ip_protocol::IPv4>() {
            //     println!("IPv4 Version: {}", ipv4_packet.version);
            // } else {
            //     eprintln!("Packet is not IPv4, skipping version check.");
            // }

    //         // Version
    //         let version = packet[14] >> 4;
    //         println!("Version {:?}", version);
    //
    //         let pac1: u8 = 0b01000101;
    //         let v = pac1 >> 4;
    //         assert!(v == 4);
    //
    //         // IHL
    //         let ihl = (packet[14] << 4 >> 4) * 32 / 8;
    //         println!("IHL len bytes {}", ihl);
    //
    //         let i = (pac1 << 4 >> 4) * 32 / 8;
    //         assert!(i == 20);
    //
    //         // DSCP
    //         let dscp = packet[15] >> 2;
    //         println!("dscp: {}", dscp);
    //
    //         let pac2: u8 = 0b00000110;
    //         let d = pac2 >> 2;
    //         assert!(d == 1);
    //
    //         // ECN
    //         let ecn = packet[15] << 6 >> 6;
    //         println!("ecn: {}", ecn);
    //
    //         let e = pac2 << 6 >> 6;
    //         assert!(e == 2);
    //
    //         // Total length
    //         let total_length = u16::from_be_bytes([packet[16], packet[17]]);
    //         println!("total len {}", total_length);
    //
    //         let pac3 = 0b11111111;
    //         let pac4 = 0b11111111;
    //         let t = u16::from_be_bytes([pac3, pac4]);
    //         assert!(t == 65535);
    //
    //         // Identification
    //         let identification = packet[18];
    //         println!("identification: {}", identification);
    //
    //         // Flags
    //         let flags = packet[19] << 5 >> 5;
    //         println!("flags: {:03b}", flags);
    //
    //         let pac5 = 0b00100010;
    //         let f = pac5 >> 5;
    //         assert!(f == 1);
    //
    //         // Fragment offset
    //         let mut fragment_offset = u16::from_be_bytes([packet[19], packet[20]]);
    //         fragment_offset = fragment_offset << 13 >> 13;
    //         println!("Fragment offset: {}", fragment_offset);
    //
    //         let pac6 = 0b0000000;
    //         let mut fr = u16::from_be_bytes([pac5, pac6]);
    //         fr = fr << 3 >> 3;
    //         assert!(fr == 512);
    //
    //         // Time to Live
    //         let time_to_live = packet[21];
    //         println!("Time to Live: {}", time_to_live);
    //
    //         // Protocol
    //         // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    //         let protocol = format!("0x{:02x}", packet[22]);
    //         println!("protocol: {}", protocol);
    //
    //         // Header checksum
    //         let header_checksum = format!("0x{:04x}", u16::from_be_bytes([packet[23], packet[24]]));
    //         println!("Header checksum: {}", header_checksum);
    //
    //         // Options
    //         // if IHL > 5: 6 to 15
    //         //let option
    //         if ihl > 20 {
    //             eprintln!("Consider implementing options capture!");
    //         }
    //
    //         // Data
    //         // for i in 25..packet.data.len() {
    //         //     let pac = packet[i];
    //         //     println!("i: {} {}", i, pac as char);
    //         // }
    //
    //         println!("ip type: {}", ip_packet.get_eth_frame().to_string_ip_type());
    //         println!("src MAC: {}", ip_packet.get_eth_frame().to_string_src_mac());
    //         println!(
    //             "dest MAC: {}",
    //             ip_packet.get_eth_frame().to_string_dest_mac()
    //         );
    //         println!("src addr: {}", ip_packet.src_addr());
    //         println!("dest addr: {}", ip_packet.dest_addr());
        }
    }
}
