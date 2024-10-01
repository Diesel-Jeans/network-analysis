use ctrlc;
use rusqlite::Connection;
use std::sync::atomic::AtomicBool;

mod database;
mod ethernet_frame;
mod ip_protocol;

static KILL_EXECUTION: AtomicBool = AtomicBool::new(false);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open("./analysis/analysisDB.db3")?;
    database::setup_database(&conn)?;

    let device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    let mut ethernet_frame: ethernet_frame::EthernetFrame = Default::default();
    let mut ipv4: ip_protocol::IPv4 = Default::default();
    let _ipv6: ip_protocol::IPv6 = Default::default();
    let mut counter: u16 = 1;
    ctrlc::set_handler(|| {
        KILL_EXECUTION.store(true, std::sync::atomic::Ordering::Relaxed);
    })?;

    while let Ok(packet) = cap.next_packet() {
        println!("received packet number: {:?}", counter);
        ethernet_frame.dest_mac = [
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
        ];
        ethernet_frame.src_mac = [
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
        ];
        ethernet_frame.ip_type = u16::from_be_bytes([packet[12], packet[13]]);
        ipv4.src_addr = [packet[30], packet[31], packet[32], packet[33]];
        ipv4.dest_addr = [packet[34], packet[35], packet[36], packet[37]];

        conn.execute(
            "INSERT INTO Packet (DestMac, SrcMac, IpType, SrcAddress, DestAddress) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                ethernet_frame.to_string_dest_mac(),
                ethernet_frame.to_string_src_mac(),
                ethernet_frame.to_string_ip_type(),
                ip_protocol::ToString::src_addr(&ipv4),
                ip_protocol::ToString::dest_addr(&ipv4)
            ),
        )?;

        if KILL_EXECUTION.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        counter += 1;
    }

    let mut stmt = conn.prepare("SELECT * FROM Packet")?;
    let mut rows = stmt.query([])?;
    println!("");
    while let Some(row) = rows.next()? {
        println!(
            "packet number id: {}",
            row.get::<usize, i64>(0)?.to_string()
        );
        println!("dest MAC: {}", row.get::<usize, String>(1)?);
        println!("src MAC: {}", row.get::<usize, String>(2)?);
        println!("ip type: {}", row.get::<usize, String>(3)?);
        println!("src addr: {}", row.get::<usize, String>(4)?);
        println!("dest addr: {}", row.get::<usize, String>(5)?);
        println!("");
    }
    Ok(())
}
