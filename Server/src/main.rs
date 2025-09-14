use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyInit};
use std::{net::UdpSocket};
use std::io::{Result};
mod db_Interface;
use db_Interface::DB_Interface;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

mod paketbuilder;
use paketbuilder::PaketBuilder;

use crate::paketbuilder::PaketReader;

const START_LOGIN: i32 = 1;
const COMPLETE_LOGIN: i32 = 2;

fn main() -> Result<()> {
    {
        let db = DB_Interface::new(String::from("Pommesfan_Bank_DB.db")).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:34254")?;

        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        let key = [0x42; 16];
        loop {
            let mut buf = [0; 1024];
            let mut encrypted = [0; 1024];
            let (amt, src) = socket.recv_from(&mut buf)?;
            //let pt = Aes128EcbDec::new(&key.into()).decrypt_padded_b2b_mut::<Pkcs7>(&buf, &mut encrypted).unwrap();
            let mut pr = PaketReader::new(&buf);
            
            let cmd = pr.get_int();
            if cmd == START_LOGIN {
                start_login(pr, &db);
            } else if cmd == COMPLETE_LOGIN {
                complete_login();
            }
        }


    } // the socket is closed here
    Ok(())
}

fn start_login(mut pr: PaketReader, db: &DB_Interface) {
    let email = pr.get_string();
    let email = email.replace("\n", "");
    let res = db.query_customer_from_email(email);
    println!("{}:{}", res.id, res.param);
}

fn complete_login() {

}