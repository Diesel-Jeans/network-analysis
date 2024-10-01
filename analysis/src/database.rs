use rusqlite::Connection;

pub fn setup_database(conn: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS Packet (
            Id    INTEGER PRIMARY KEY,
            DestMac  TEXT NOT NULL,
            SrcMac  TEXT NOT NULL,
            IpType  TEXT NOT NULL,
            SrcAddress  TEXT NOT NULL,
            DestAddress  TEXT NOT NULL
        )",
        (),
    )?;
    Ok(())
}
