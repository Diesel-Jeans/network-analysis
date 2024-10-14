#![crate_name = "doc"]

use libc::timeval;
use pcap::Packet;
use std::usize;

use super::ip_protocol;
use crate::{
    ethernet_frame,
    ip_protocol::{ETH_HLEN, IP_MIN_HLEN},
};
use ethernet_frame::EthernetFrame;

pub struct IPv4 {
    /// Time when packet was captured
    pub time_stamp: timeval,
    /// (14-bytes) Ethernet Frame
    pub eth_frame: EthernetFrame,
    /// (4-bit) Version of IP packet - IPv4 equal to 4
    pub version: u8,
    /// (4-bit) Internet Header Length (IHL)
    pub ihl: u8,
    /// (6-bit) Differentiated Services Code Point (DSCP)
    pub dscp: u8,
    /// (2-bit) Explicit Congestion Notification (ECN)
    pub ecn: u8,
    /// (16-bit) Total Length of packet size
    pub total_length: u16,
    /// (16-bit) Identification - Used for fragmentation and reassembly
    pub identification: u16,
    /// (3-bit) Flags, order: MSB to LSB - Used to control or identify fragments
    /// bit 0: Reserved - Always zero
    /// bit 1: DF (Don't Fragment)
    /// bit 2: MF (More Fragments) - Set on all fragmented packets, except the last
    pub flags: String,
    /// (13-bit) Fragment offset - Specifies the position of the fragment in the original
    /// fragmented IP packet
    pub fragment_offset: u16,
    /// (8-bit) Time to Live - Prevent routing loop by decrementing live field by 1
    pub time_to_live: u8,
    /// (8-bit) Protocol that is encapsulated in the IP packet
    /// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    pub protocol: String,
    /// (16-bit) Header Checksum - Receiver can check for errors in the header
    pub header_checksum: String,
    /// (32-bit) Source address - May be affected by NAT
    pub src_addr: [u8; 4],
    /// (32-bit) Destination address - May be affected by NAT
    pub dest_addr: [u8; 4],
    /// (40-bit) Options that are not often used - Active if IHL > 20 bytes (max 60 bytes)
    /// Options Types:
    /// Single-byte: No operation (Type 1), End of option (Type 0)
    /// Multiple-byte: Record route (Type 7), Strict source route (Type 137),
    /// Loose source route (type 131), Timestamp (Type 68)
    pub options: Vec<Option>,
    /// (20-bytes to 65,535-bytes) The packet payload - Not included in the checksum
    pub data: Vec<u8>,
}

/// Option can max be 40-bytes, where type+size+data+padding = 1+1+(4*9)+2 = 40
pub struct Option {
    /// (8-bit) Type of option
    /// Option behavior:
    /// (1-bit) Set to 1 if the options need to be copied into all fragments of a fragmented packet.
    /// (2-bit) 0 is for control options, and 2 is for debugging and measurement. 1 and 3 are reserved
    /// (5-bit) Specifies an option
    pub r#type: u8,
    /// (8-bit) The size of the option including type, size, data
    pub length: u8,
    /// (36-bytes) Data
    pub data: Vec<u8>,
}

impl IPv4 {
    fn time_stamp(packet: &Packet) -> timeval {
        packet.header.ts
    }

    fn version(packet: &Packet) -> u8 {
        packet[14] >> 4
    }

    fn ihl(packet: &Packet) -> u8 {
        (packet[14] & 0x0F) * 4
    }

    fn dscp(packet: &Packet) -> u8 {
        packet[15] >> 2
    }

    fn ecn(packet: &Packet) -> u8 {
        packet[15] & 0x03
    }

    fn total_length(packet: &Packet) -> u16 {
        u16::from_be_bytes([packet[16], packet[17]])
    }

    fn identification(packet: &Packet) -> u16 {
        u16::from_be_bytes([packet[18], packet[19]])
    }

    fn flags(packet: &Packet) -> String {
        format!("{:03b}", packet[20] >> 5)
    }

    fn fragment_offset(packet: &Packet) -> u16 {
        u16::from_be_bytes([packet[20], packet[21]]) & 0x1FFF
    }

    fn time_to_live(packet: &Packet) -> u8 {
        packet[22]
    }

    fn protocol(packet: &Packet) -> String {
        format!("0x{:02x}", packet[23])
    }

    fn header_checksum(packet: &Packet) -> String {
        format!("0x{:04x}", u16::from_be_bytes([packet[24], packet[25]]))
    }

    fn src_addr(packet: &Packet) -> [u8; 4] {
        [packet[26], packet[27], packet[28], packet[29]]
    }

    fn dst_addr(packet: &Packet) -> [u8; 4] {
        [packet[30], packet[31], packet[32], packet[33]]
    }

    fn options(packet: &Packet) -> Vec<Option> {
        let mut options: Vec<Option> = vec![];
        let packet_header_len = IPv4::ihl(packet) as usize;

        if packet_header_len <= IP_MIN_HLEN {
            return options;
        }

        fn create_multi_byte_option(
            offset: usize,
            option_len: usize,
            packet: &Packet,
        ) -> (usize, Option) {
            let r#type = packet[offset];
            let length = packet[offset + 1];
            let mut data: Vec<u8> = vec![];

            let mut i = 2;
            let end_offset = loop {
                data.push(packet[offset + i]);

                if i >= option_len - 1 {
                    break i;
                }

                i += 1;
            };

            (
                offset + end_offset,
                Option {
                    r#type,
                    length,
                    data,
                },
            )
        }

        // When IP header length is > 20 bytes there are option(s)
        // The ethernet frame length is 14
        // Create option(s) from byte 34 = 20 + 14
        let mut i = IP_MIN_HLEN + ETH_HLEN;
        while i < ETH_HLEN + packet_header_len - 1 {
            match packet[i] {
                0 => {
                    options.push(Option {
                        r#type: 0,
                        length: 0,
                        data: vec![],
                    });
                    i += 1;
                }
                1 => {
                    options.push(Option {
                        r#type: 1,
                        length: 0,
                        data: vec![],
                    });
                    i += 1;
                }
                _ => {
                    let (offset, opt) = create_multi_byte_option(i, packet[i + 1] as usize, packet);
                    options.push(opt);
                    i = offset;
                    println!("new i {}", i);
                }
            }
        }

        options
    }

    fn data(packet: &Packet) -> Vec<u8> {
        let packet_header_len = IPv4::ihl(packet) as usize;

        let mut data_vec = vec![];
        for i in (ETH_HLEN + packet_header_len)..packet.data.len() {
            data_vec.push(packet[i]);
        }

        data_vec
    }
}

impl IPv4 {
    fn to_string_addr(addr: [u8; 4]) -> String {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }

    pub fn to_string_src_addr(&self) -> String {
        IPv4::to_string_addr(self.src_addr)
    }

    pub fn to_string_dst_addr(&self) -> String {
        IPv4::to_string_addr(self.dest_addr)
    }
}

impl ip_protocol::Packet for IPv4 {
    fn serialize(
        packet: &Packet,
        eth_frame: ethernet_frame::EthernetFrame,
    ) -> Box<dyn ip_protocol::Packet> {
        Box::new(IPv4 {
            time_stamp: IPv4::time_stamp(packet),
            eth_frame,
            version: IPv4::version(packet),
            ihl: IPv4::ihl(packet),
            dscp: IPv4::dscp(packet),
            ecn: IPv4::ecn(packet),
            total_length: IPv4::total_length(packet),
            identification: IPv4::identification(packet),
            flags: IPv4::flags(packet),
            fragment_offset: IPv4::fragment_offset(packet),
            time_to_live: IPv4::time_to_live(packet),
            protocol: IPv4::protocol(packet),
            header_checksum: IPv4::header_checksum(packet),
            src_addr: IPv4::src_addr(packet),
            dest_addr: IPv4::dst_addr(packet),
            options: IPv4::options(packet),
            data: IPv4::data(packet),
        })
    }

    fn get_eth_frame(&self) -> &EthernetFrame {
        &self.eth_frame
    }

    fn get_time_stamp(&self) -> timeval {
        self.time_stamp
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::ip_protocol::ipv4;
    use pcap::{Packet, PacketHeader};

    struct IPv4Packet {}

    impl IPv4Packet {
        pub fn new(data: &[u8]) -> Packet {
            Packet {
                header: &PacketHeader {
                    ts: libc::timeval {
                        tv_sec: 0 as libc::time_t,
                        tv_usec: 0 as libc::suseconds_t,
                    },
                    caplen: 0,
                    len: 0,
                },
                data,
            }
        }
    }

    #[test]
    fn test_version() {
        let mut packet = [0u8; 60];
        packet[14] = 0b01000101;
        let ipv4_packet = IPv4Packet::new(&packet);
        let version = ipv4::IPv4::version(&ipv4_packet);
        assert_eq!(version, 4);
    }

    #[test]
    fn test_ihl() {
        let mut packet = [0u8; 60];
        packet[14] = 0b01000101;
        let ipv4_packet = IPv4Packet::new(&packet);
        let ihl = ipv4::IPv4::ihl(&ipv4_packet);
        assert_eq!(ihl, 20);
    }

    #[test]
    fn test_dscp() {
        let mut packet = [0u8; 60];
        packet[15] = 0b00000110;
        let ipv4_packet = IPv4Packet::new(&packet);
        let dscp = ipv4::IPv4::dscp(&ipv4_packet);
        assert_eq!(dscp, 1);
    }

    #[test]
    fn test_ecn() {
        let mut packet = [0u8; 60];
        packet[15] = 0b01000101;
        let ipv4_packet = IPv4Packet::new(&packet);
        let ecn = ipv4::IPv4::ecn(&ipv4_packet);
        assert_eq!(ecn, 1);
    }

    #[test]
    fn test_total_length() {
        let mut packet = [0u8; 60];
        packet[16] = 0b11111111;
        packet[17] = 0b11111111;
        let ipv4_packet = IPv4Packet::new(&packet);
        let total_length = ipv4::IPv4::total_length(&ipv4_packet);
        assert_eq!(total_length, 65535);
    }

    #[test]
    fn test_identification() {
        let mut packet = [0u8; 60];
        packet[18] = 0b00000000;
        packet[19] = 0b00000001;
        let ipv4_packet = IPv4Packet::new(&packet);
        let identification = ipv4::IPv4::identification(&ipv4_packet);
        assert_eq!(identification, 1);
    }

    #[test]
    fn test_flags() {
        let mut packet = [0u8; 60];
        packet[20] = 0b00101111;
        let ipv4_packet = IPv4Packet::new(&packet);
        let flags = ipv4::IPv4::flags(&ipv4_packet);
        assert_eq!(flags, "001");
    }

    #[test]
    fn test_fragment_offset() {
        let mut packet = [0u8; 60];
        packet[20] = 0b00100010;
        packet[21] = 0b00000000;
        let ipv4_packet = IPv4Packet::new(&packet);
        let fragment_offset = ipv4::IPv4::fragment_offset(&ipv4_packet);
        assert_eq!(fragment_offset, 512);
    }

    #[test]
    fn test_time_to_live() {
        let mut packet = [0u8; 60];
        packet[22] = 0b00000001;
        let ipv4_packet = IPv4Packet::new(&packet);
        let time_to_live = ipv4::IPv4::time_to_live(&ipv4_packet);
        assert_eq!(time_to_live, 1);
    }

    #[test]
    fn test_protocol() {
        let mut packet = [0u8; 60];
        packet[23] = 0b00000100;
        let ipv4_packet = IPv4Packet::new(&packet);
        let protocol = ipv4::IPv4::protocol(&ipv4_packet);
        assert_eq!(protocol, "0x04");
    }

    #[test]
    fn test_header_checksum() {
        let mut packet = [0u8; 60];
        packet[24] = 0b10111000;
        packet[25] = 0b01100001;
        let ipv4_packet = IPv4Packet::new(&packet);
        let packet_checksum = ipv4::IPv4::header_checksum(&ipv4_packet);
        assert_eq!(packet_checksum, "0xb861");
    }

    #[test]
    fn test_src_addr() {
        let mut packet = [0u8; 60];
        packet[26] = 0b11000000;
        packet[27] = 0b10101000;
        packet[28] = 0b01010111;
        packet[29] = 0b01111100;
        let ipv4_packet = IPv4Packet::new(&packet);
        let src_addr = ipv4::IPv4::src_addr(&ipv4_packet);
        assert_eq!(src_addr, [192, 168, 87, 124]);
    }

    #[test]
    fn test_dst_addr() {
        let mut packet = [0u8; 60];
        packet[30] = 0b11000000;
        packet[31] = 0b10101000;
        packet[32] = 0b01010111;
        packet[33] = 0b01000110;
        let ipv4_packet = IPv4Packet::new(&packet);
        let dst_addr = ipv4::IPv4::dst_addr(&ipv4_packet);
        assert_eq!(dst_addr, [192, 168, 87, 70]);
    }

    #[test]
    fn test_no_options() {
        let mut packet = [0u8; 60];
        packet[14] = 0x5;
        let ipv4_packet = IPv4Packet::new(&packet);
        let options = ipv4::IPv4::options(&ipv4_packet);
        assert_eq!(options.len(), 0);
    }

    #[test]
    fn test_multiple_options() {
        // No Operation (1 byte)
        const NOP: u8 = 1;
        // Record Route (Type 7)
        const RR_TYPE: u8 = 7;
        // Record Route length (15 bytes)
        const RR_LEN: u8 = 15;

        let mut packet = [0u8; 50];
        // Set IHL = 9 (20 bytes + 15 bytes)
        packet[14] = 0x9;

        packet[34] = NOP; // Option: No Operation (1 byte)
        packet[35] = RR_TYPE; // Option: Record Route (type 7) (1 byte)
        packet[36] = RR_LEN; // Length of the Record Route option (15 bytes)
        packet[37] = 4; // Pointer to first available entry

        // IP addr
        packet[38] = 192;
        packet[39] = 168;
        packet[40] = 1;
        packet[41] = 1;

        // IP addr
        packet[42] = 192;
        packet[43] = 168;
        packet[44] = 1;
        packet[45] = 2;

        // IP addr
        packet[46] = 192;
        packet[47] = 168;
        packet[48] = 1;
        packet[49] = 3;

        let ipv4_packet = IPv4Packet::new(&packet);
        let options = ipv4::IPv4::options(&ipv4_packet);

        assert_eq!(options.len(), 2);
        assert_eq!(options[0].length, 0);
        assert_eq!(options[0].r#type, NOP);
        assert_eq!(options[0].data, vec![]);

        assert_eq!(options[1].r#type, RR_TYPE);
        assert_eq!(options[1].length, RR_LEN);
        assert_eq!(
            options[1].data,
            vec![4, 192, 168, 1, 1, 192, 168, 1, 2, 192, 168, 1, 3]
        );
    }

    #[test]
    fn test_data() {
        let mut packet = [0u8; 49];
        packet[14] = 0b01000101;
        packet[34] = 0b01001001;
        packet[35] = 0b00100000;
        packet[36] = 0b01100001;
        packet[37] = 0b01101101;
        packet[38] = 0b00100000;
        packet[39] = 0b01110000;
        packet[40] = 0b01101100;
        packet[41] = 0b01100001;
        packet[42] = 0b01101001;
        packet[43] = 0b01101110;
        packet[44] = 0b01110100;
        packet[45] = 0b01100101;
        packet[46] = 0b01111000;
        packet[47] = 0b01110100;
        packet[48] = 0b00100001;
        let ipv4_packet = IPv4Packet::new(&packet);
        let data = ipv4::IPv4::data(&ipv4_packet);
        let mut buffer: String = "".to_string();
        for i in data.iter() {
            let x = *i as char;
            buffer.push(x);
        }
        assert_eq!(buffer, "I am plaintext!");
    }
}
