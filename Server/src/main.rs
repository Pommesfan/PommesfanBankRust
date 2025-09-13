use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyInit};
use std::{net::UdpSocket};
use std::io::{Result};
mod db_Interface;
use db_Interface::DB_Interface;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

mod paketbuilder;
use paketbuilder::PaketBuilder;

use crate::paketbuilder::PaketReader;


fn main() -> Result<()> {
    {
        let mut pb = PaketBuilder::new();
        pb.add_string(String::from("Hallo"));
        pb.add_string(String::from("Hi"));

        let mut pr = PaketReader::new(pb.get_paket());
        println!("{}", pr.get_string());
        println!("{}", pr.get_string());

        let db = DB_Interface::new(String::from("Pommesfan_Bank_DB.db"));
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
