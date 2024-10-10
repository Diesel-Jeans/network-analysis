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
