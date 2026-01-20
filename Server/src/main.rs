use std::io::Result;
use std::thread;
use std::sync::{Arc, Mutex};
use std::net::{TcpListener, UdpSocket};
mod db_interface;
use db_interface::DbInterface;
mod sessions;
use sessions::SessionList;
mod customer_service;
use customer_service::CustomerService;
use common::utils::*;

fn main() -> Result<()> {
    {
        let db = DbInterface::new(String::from("Pommesfan_Bank_DB.db")).unwrap();
        let socket_read = UdpSocket::bind(create_udp_read_url())?;
        let socket_write = UdpSocket::bind(create_udp_write_url())?;
        let ongoing_session_list = SessionList::new();
        let session_list = SessionList::new();

        let db_arc = Arc::new(Mutex::new(db));
        let socket_arc_read = Arc::new(Mutex::new(socket_read));
        let socket_arc_write = Arc::new(Mutex::new(socket_write));
        let ongoing_session_list_arc = Arc::new(Mutex::new(ongoing_session_list));
        let session_list_arc = Arc::new(Mutex::new(session_list));


        for n in 0 .. 4 {
            let db_arc = Arc::clone(&db_arc);
            let socket_arc_read = Arc::clone(&socket_arc_read);
            let socket_arc_write = Arc::clone(&socket_arc_write);
            let ongoing_session_list_arc = Arc::clone(&ongoing_session_list_arc);
            let session_list_arc = Arc::clone(&session_list_arc);
            let tcp_listener = TcpListener::bind(create_tcp_url(n)).unwrap();
            let customer_service = CustomerService::new(db_arc, socket_arc_read, socket_arc_write, ongoing_session_list_arc, session_list_arc, FIRST_TCP_PORT + n, tcp_listener);
            thread::spawn(move || {
                customer_service.routine();
            });
        }
        let _ = thread::spawn(|| {
            server_routine();
        }).join();
        Ok(())
    }
}

fn server_routine() {
    loop {
        println!("1 eingeben für Konto anlegen");
        if read_int() == 1 {

        }
    }
}