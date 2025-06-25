use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use hex_literal::hex;
use std::{net::UdpSocket, str};

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;


fn main() -> std::io::Result<()> {
    {
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