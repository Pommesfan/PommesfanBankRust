use std::{cmp, net::UdpSocket, io};

fn main() {
	let buf = [4, 3, 2, 2, 1, 4, 3, 2, 2, 1];
	let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    println!("Kommando eingeben:");
    let mut cmd = String::new();
    io::stdin().read_line(&mut cmd);
	socket.send_to(cmd.as_bytes(), "127.0.0.1:34254").expect("couldn't send data");
}