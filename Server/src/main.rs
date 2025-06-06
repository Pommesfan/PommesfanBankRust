use std::{net::UdpSocket, str};

fn main() -> std::io::Result<()> {
    {
        let socket = UdpSocket::bind("127.0.0.1:34254")?;

        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        println!("{:?}", "Waiting for input");
        let mut buf = [0; 10];
        let (amt, src) = socket.recv_from(&mut buf)?;
        let res = String::from_utf8(buf.to_vec()).unwrap();
        println!("{}", &res);
    } // the socket is closed here
    Ok(())
}