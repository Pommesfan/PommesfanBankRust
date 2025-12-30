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
        let socket = UdpSocket::bind(create_udp_url())?;
        let ongoing_session_list = SessionList::new();
        let session_list = SessionList::new();

        let db_arc = Arc::new(Mutex::new(db));
        let socket_arc = Arc::new(Mutex::new(socket));
        let ongoing_session_list_arc = Arc::new(Mutex::new(ongoing_session_list));
        let session_list_arc = Arc::new(Mutex::new(session_list));


        for n in 0 .. 4 {
            let db_arc = Arc::clone(&db_arc);
            let socket_arc = Arc::clone(&socket_arc);
            let ongoing_session_list_arc = Arc::clone(&ongoing_session_list_arc);
            let session_list_arc = Arc::clone(&session_list_arc);
            let tcp_listener = TcpListener::bind(create_tcp_url(n)).unwrap();
            let customer_service = CustomerService::new(db_arc, socket_arc, ongoing_session_list_arc, session_list_arc, FIRST_TCP_PORT + n, tcp_listener);
            let _ = thread::spawn(move || {
                customer_service.routine();
            }).join();
        }
        Ok(())
    }
}
