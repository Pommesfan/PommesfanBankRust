use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyInit};
use std::{net::UdpSocket};
use rusqlite::{Connection};
use std::io::{Result, Error};

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;


fn main() -> Result<()> {
    {
        //let connection = Connection::open("Hallo")?;
        let db = DB_Interface::new(String::from("Hallo"));
        let socket = UdpSocket::bind("127.0.0.1:34254")?;

        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        println!("{:?}", "Waiting for input");
        let mut buf = [0; 32];
        let (amt, src) = socket.recv_from(&mut buf)?;

        let key = [0x42; 16];
        let mut buf2 = [0u8; 48];
        let pt = Aes128EcbDec::new(&key.into()).decrypt_padded_b2b_mut::<Pkcs7>(&buf, &mut buf2).unwrap();

        let res = String::from_utf8(pt.to_vec()).unwrap();
        println!("{}", &res);
    } // the socket is closed here
    Ok(())
}

pub struct DB_Interface{
    con: Connection,
}

impl DB_Interface {
    fn new(url: String) -> rusqlite::Result<DB_Interface> {
        let is_initiallized = std::fs::exists(&url).unwrap();
        let con = Connection::open(&url)?;
        let db = DB_Interface {
            con: con,
        };
        if(!is_initiallized) {
            db.init_database();
        }
        Ok(db)
    }

    fn init_database(&self) {
            let cmd = std::fs::read_to_string("Server/src/SQL-Scripts/create_tables.sql").unwrap();
            self.con.execute_batch(&cmd).unwrap();
            let cmd = std::fs::read_to_string("Server/src/SQL-Scripts/create_example_customers.sql").unwrap();
            self.con.execute_batch(&cmd).unwrap();
    }
}