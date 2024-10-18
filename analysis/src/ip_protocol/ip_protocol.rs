use crate::ethernet_frame::EthernetFrame;
use libc::timeval;
use std::any::Any;

pub trait Packet {
    fn serialize(packet: &pcap::Packet, eth_frame: EthernetFrame) -> Box<dyn Packet>
    where
        Self: Sized;

    #[allow(dead_code)]
    fn get_eth_frame(&self) -> &EthernetFrame;
    fn get_time_stamp(&self) -> timeval;
    fn as_any(&self) -> &dyn Any;
}

pub fn packet_filter<U>(
    packet: Option<Box<dyn Packet>>,
    predicate: impl Fn(&U) -> bool,
) -> Option<Box<dyn Packet>>
where
    U: 'static + Packet,
{
    packet.and_then(|p| {
        if let Some(target_packet) = p.as_any().downcast_ref::<U>() {
            if predicate(target_packet) {
                Some(p)
            } else {
                None
            }
        } else {
           Some(p) 
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::{ethernet_frame::EthernetFrame, ip_protocol::{Packet, IPv4, packet_filter}};
    use libc::timeval;
    use pcap::{Packet as PcapPacket, PacketHeader};

    pub struct OtherProtocol { 
        pub time_stamp: timeval,
        pub eth_frame: EthernetFrame,
        pub ihl: u8,
    }

    impl OtherProtocol {
        fn time_stamp(packet: &PcapPacket) -> timeval {
            packet.header.ts
        }

        fn ihl(packet: &PcapPacket) -> u8 {
            (packet[14] & 0x0F) * 4
        }

    }

    impl Packet for OtherProtocol {
        fn serialize(packet: &pcap::Packet, eth_frame: EthernetFrame) -> Box<dyn Packet>
            where
                Self: Sized {
            Box::new(OtherProtocol {
                time_stamp: OtherProtocol::time_stamp(packet),
                eth_frame,
                ihl: OtherProtocol::ihl(packet),
            })
        }

        fn get_eth_frame(&self) -> &EthernetFrame {
            &self.eth_frame
        }

       fn get_time_stamp(&self) -> libc::timeval {
            self.time_stamp
        } 

       fn as_any(&self) -> &dyn std::any::Any {
           self
       }
    }

    pub fn new_packet(data: &[u8]) -> PcapPacket<'_> {
        PcapPacket {
            header: &PacketHeader {
                ts: libc::timeval { 
                    tv_sec: 0 as libc::time_t, 
                    tv_usec: 0 as libc::time_t, 
                },
                caplen: 0, 
                len: 0, 
            },
            data, 
        }
    }

    #[test]
    fn test_packet_filter_keep() {
        let mut  packet_data1 = [0u8; 60];
        packet_data1[14] = 0x5;
        
        let packet = new_packet(&packet_data1);
        let eth_frame = EthernetFrame::serialize(&packet);
        let mut ip_packet = Some(IPv4::serialize(&packet, eth_frame));

        ip_packet = packet_filter::<IPv4>(ip_packet, |p| {
            p.ihl == 20
        });

        if let Some(packet) = ip_packet {
            let packet_ref: &dyn Packet = &*packet;
            let ipv4_packet: &IPv4 = packet_ref
                .as_any()
                .downcast_ref::<IPv4>()
                .expect("Not IPv4");

            assert_eq!(ipv4_packet.ihl, 20);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_packet_filter_remove() {
        let mut  packet_data1 = [0u8; 60];
        packet_data1[14] = 0x5;
        
        let packet = new_packet(&packet_data1);
        let eth_frame = EthernetFrame::serialize(&packet);
        let mut ip_packet = Some(IPv4::serialize(&packet, eth_frame));

        ip_packet = packet_filter::<IPv4>(ip_packet, |p| {
            p.ihl > 20
        });

        if let Some(packet) = ip_packet {
            let packet_ref: &dyn Packet = &*packet;
            let ipv4_packet: &IPv4 = packet_ref
                .as_any()
                .downcast_ref::<IPv4>()
                .expect("Not IPv4");

            assert_eq!(ipv4_packet.ihl, 20);
        } else {
            assert!(true);
        }
    }

    #[test]
    fn test_packet_filter_skip() {
        let mut packet_data = [0u8; 60];
        // OtherProtocol: 0x0900
        // packet_data[12] = 0x0;
        // packet_data[13] = 0x9;
        packet_data[14] = 0x5;

        let packet = new_packet(&packet_data);
        let eth_frame = EthernetFrame::serialize(&packet);
        let mut ip_packet = Some(IPv4::serialize(&packet, eth_frame));

        ip_packet = packet_filter::<OtherProtocol>(ip_packet, |p| {
            p.ihl == 20
        });

        ip_packet = packet_filter::<IPv4>(ip_packet, |p| {
            p.ihl == 20
        });
        
        if let Some(packet) = ip_packet {
            let packet_ref: &dyn Packet = &*packet;
            let ipv4_packet: &IPv4 = packet_ref
                .as_any()
                .downcast_ref::<IPv4>()
                .expect("Not IPv4");

            assert_eq!(ipv4_packet.ihl, 20);
        } else {
            assert!(false);
        }
    }
}

