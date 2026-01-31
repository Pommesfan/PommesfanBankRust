use std::collections::BTreeMap;

pub struct Session {
    pub session_id: String,
    pub customer_id: String,
    pub session_crypto: [u8; 32],
}

impl Session {
    pub fn new(p_session_id: String, p_customer_id: String, p_session_crypto: [u8; 32]) -> Session {
        Session{
            session_id: p_session_id,
            customer_id: p_customer_id,
            session_crypto: p_session_crypto,
        }
    }
}

impl Clone for Session {
    fn clone(&self) -> Session {
        Session {
            session_id: self.session_id.clone(),
            customer_id: self.customer_id.clone(),
            session_crypto: self.session_crypto.clone(),
        }
    }
}

pub struct SessionList {
    map: BTreeMap<String, Session>,
}

impl SessionList {
    pub fn new() ->SessionList {
        SessionList {
            map: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, s: Session) {
        self.map.insert(s.session_id.clone(), s);
    }

    pub fn get_session(&self, session_id: &String) -> &Session {
        self.map.get(session_id).unwrap()
    }

    pub fn remove_session(&mut self, session_id: &String) -> Session{
        self.map.remove(session_id).unwrap()
    }
}