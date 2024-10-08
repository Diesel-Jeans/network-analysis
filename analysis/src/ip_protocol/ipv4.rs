#![crate_name = "doc"]

use pcap::Packet;
use std::usize;

use super::ip_protocol;
use crate::{
    ethernet_frame,
    ip_protocol::{ETH_HLEN, IP_MIN_HLEN},
};
use ethernet_frame::EthernetFrame;

pub struct IPv4 {
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
        let packet_header_len = IPv4::ihl(packet);

        if packet_header_len <= 20 {
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
            let res = loop {
                data.push(packet[offset + i]);

                if i >= option_len - 1 {
                    break i;
                }

                i += 1;
            };

            (
                res + offset,
                Option {
                    r#type,
                    length,
                    data,
                },
            )
        }

        let mut i = IP_MIN_HLEN + ETH_HLEN;
        while i < packet_header_len as usize + ETH_HLEN - 1 {
            match packet[i] & 0xFF {
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
                    let (res, opt) = create_multi_byte_option(i, packet[i + 1] as usize, packet);
                    options.push(opt);
                    i = res;
                    println!("new i {}", i);
                }
            }
        }

        options
    }

    fn data(packet: &Packet) -> Vec<u8> {
        let eth_frame_len: usize = 14;
        let packet_len = IPv4::ihl(packet);

        let mut data_vec = vec![];
        for i in (eth_frame_len + packet_len as usize)..packet.data.len() {
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
        const BYTE: u8 = 0b01000101;
        let mut header = [0u8; 60];
        header[14] = BYTE;
        let packet = IPv4Packet::new(&header);
        let version = ipv4::IPv4::version(&packet);
        assert_eq!(version, 4);
    }

    #[test]
    fn test_ihl() {
        const BYTE: u8 = 0b01000101;
        let mut header = [0u8; 60];
        header[14] = BYTE;
        let packet = IPv4Packet::new(&header);
        let ihl = ipv4::IPv4::ihl(&packet);
        assert_eq!(ihl, 20);
    }

    #[test]
    fn test_dscp() {
        const BYTE: u8 = 0b00000110;
        let mut header = [0u8; 60];
        header[15] = BYTE;
        let packet = IPv4Packet::new(&header);
        let dscp = ipv4::IPv4::dscp(&packet);
        assert_eq!(dscp, 1);
    }

    #[test]
    fn test_ecn() {
        const BYTE: u8 = 0b01000101;
        let mut header = [0u8; 60];
        header[15] = BYTE;
        let packet = IPv4Packet::new(&header);
        let ecn = ipv4::IPv4::ecn(&packet);
        assert_eq!(ecn, 1);
    }

    #[test]
    fn test_total_length() {
        const BYTE1: u8 = 0b11111111;
        const BYTE2: u8 = 0b11111111;
        let mut header = [0u8; 60];
        header[16] = BYTE1;
        header[17] = BYTE2;
        let packet = IPv4Packet::new(&header);
        let total_length = ipv4::IPv4::total_length(&packet);
        assert_eq!(total_length, 65535);
    }

    #[test]
    fn test_identification() {
        const BYTE1: u8 = 0b00000000;
        const BYTE2: u8 = 0b00000001;
        let mut header = [0u8; 60];
        header[18] = BYTE1;
        header[19] = BYTE2;
        let packet = IPv4Packet::new(&header);
        let identification = ipv4::IPv4::identification(&packet);
        assert_eq!(identification, 1);
    }

    #[test]
    fn test_flags() {
        const BYTE: u8 = 0b00101111;
        let mut header = [0u8; 60];
        header[20] = BYTE;
        let packet = IPv4Packet::new(&header);
        let flags = ipv4::IPv4::flags(&packet);
        assert_eq!(flags, "001");
    }

    #[test]
    fn test_fragment_offset() {
        const BYTE1: u8 = 0b00100010;
        const BYTE2: u8 = 0b00000000;
        let mut header = [0u8; 60];
        header[20] = BYTE1;
        header[21] = BYTE2;
        let packet = IPv4Packet::new(&header);
        let fragment_offset = ipv4::IPv4::fragment_offset(&packet);
        assert_eq!(fragment_offset, 512);
    }

    #[test]
    fn test_time_to_live() {
        const BYTE: u8 = 0b00000001;
        let mut header = [0u8; 60];
        header[22] = BYTE;
        let packet = IPv4Packet::new(&header);
        let time_to_live = ipv4::IPv4::time_to_live(&packet);
        assert_eq!(time_to_live, 1);
    }

    #[test]
    fn test_protocol() {
        const BYTE: u8 = 0b00000100;
        let mut header = [0u8; 60];
        header[23] = BYTE;
        let packet = IPv4Packet::new(&header);
        let protocol = ipv4::IPv4::protocol(&packet);
        assert_eq!(protocol, "0x04");
    }

    #[test]
    fn test_header_checksum() {
        const BYTE1: u8 = 0b10111000;
        const BYTE2: u8 = 0b01100001;
        let mut header = [0u8; 60];
        header[24] = BYTE1;
        header[25] = BYTE2;
        let packet = IPv4Packet::new(&header);
        let header_checksum = ipv4::IPv4::header_checksum(&packet);
        assert_eq!(header_checksum, "0xb861");
    }

    #[test]
    fn test_src_addr() {
        const BYTE1: u8 = 0b11000000;
        const BYTE2: u8 = 0b10101000;
        const BYTE3: u8 = 0b01010111;
        const BYTE4: u8 = 0b01111100;
        let mut header = [0u8; 60];
        header[26] = BYTE1;
        header[27] = BYTE2;
        header[28] = BYTE3;
        header[29] = BYTE4;
        let packet = IPv4Packet::new(&header);
        let src_addr = ipv4::IPv4::src_addr(&packet);
        assert_eq!(src_addr, [192, 168, 87, 124]);
    }

    #[test]
    fn test_dst_addr() {
        const BYTE1: u8 = 0b11000000;
        const BYTE2: u8 = 0b10101000;
        const BYTE3: u8 = 0b01010111;
        const BYTE4: u8 = 0b01000110;
        let mut header = [0u8; 60];
        header[30] = BYTE1;
        header[31] = BYTE2;
        header[32] = BYTE3;
        header[33] = BYTE4;
        let packet = IPv4Packet::new(&header);
        let dst_addr = ipv4::IPv4::dst_addr(&packet);
        assert_eq!(dst_addr, [192, 168, 87, 70]);
    }

    #[test]
    fn test_no_options() {
        let mut header = [0u8; 60];
        header[14] = 0x5;
        let packet = IPv4Packet::new(&header);
        let options = ipv4::IPv4::options(&packet);
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

        let mut header = [0u8; 50];
        // Set IHL = 9 (20 bytes + 15 bytes)
        header[14] = 0x9;

        header[34] = NOP; // Option: No Operation (1 byte)
        header[35] = RR_TYPE; // Option: Record Route (type 7) (1 byte)
        header[36] = RR_LEN; // Length of the Record Route option (15 bytes)
        header[37] = 4; // Pointer to first available entry

        // IP addr
        header[38] = 192;
        header[39] = 168;
        header[40] = 1;
        header[41] = 1;

        // IP addr
        header[42] = 192;
        header[43] = 168;
        header[44] = 1;
        header[45] = 2;

        // IP addr
        header[46] = 192;
        header[47] = 168;
        header[48] = 1;
        header[49] = 3;

        let packet = IPv4Packet::new(&header);
        let options = ipv4::IPv4::options(&packet);

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
        const BYTE1: u8 = 0b01000101;
        const BYTE2: u8 = 0b01001001;
        const BYTE3: u8 = 0b00100000;
        const BYTE4: u8 = 0b01100001;
        const BYTE5: u8 = 0b01101101;
        const BYTE6: u8 = 0b00100000;
        const BYTE7: u8 = 0b01110000;
        const BYTE8: u8 = 0b01101100;
        const BYTE9: u8 = 0b01100001;
        const BYTE10: u8 = 0b01101001;
        const BYTE11: u8 = 0b01101110;
        const BYTE12: u8 = 0b01110100;
        const BYTE13: u8 = 0b01100101;
        const BYTE14: u8 = 0b01111000;
        const BYTE15: u8 = 0b01110100;
        const BYTE16: u8 = 0b00100001;
        let mut header = [0u8; 49];
        header[14] = BYTE1;
        header[34] = BYTE2;
        header[35] = BYTE3;
        header[36] = BYTE4;
        header[37] = BYTE5;
        header[38] = BYTE6;
        header[39] = BYTE7;
        header[40] = BYTE8;
        header[41] = BYTE9;
        header[42] = BYTE10;
        header[43] = BYTE11;
        header[44] = BYTE12;
        header[45] = BYTE13;
        header[46] = BYTE14;
        header[47] = BYTE15;
        header[48] = BYTE16;
        let packet = IPv4Packet::new(&header);
        let data = ipv4::IPv4::data(&packet);
        let mut buffer: String = "".to_string();
        for i in data.iter() {
            let x = *i as char;
            buffer.push(x);
        }
        assert_eq!(buffer, "I am plaintext!");
    }
}
