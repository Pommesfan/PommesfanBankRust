use rusqlite::{Connection};

pub struct DbInterface{
    con: Connection,
}

impl DbInterface {
    pub fn new(url: String) -> rusqlite::Result<DbInterface> {
        let is_initiallized = std::fs::exists(&url).unwrap();
        let con = Connection::open(&url)?;
        let db = DbInterface {
            con: con,
        };
        if !is_initiallized {
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

    pub fn query_customer_from_id(&self, customer_id: &String) -> (String, String) {
        let sql = String::from("select customer_id, password from customer where customer_id = ?1;");
        self.query_customer(&sql, customer_id)
    }
        

    pub fn query_customer_from_email(&self, email: &String) -> (String, String) {
        let sql = String::from("select customer_id, password from customer where email = ?1;");
        self.query_customer(&sql, email)
    }

    fn query_customer(&self, sql: &String, value: &String) -> (String, String) {
        let mut stmt = self.con.prepare(&sql).unwrap();
        stmt.query_one([value], |row| {
            Ok((row.get(0)?, row.get(1)?))
        }).unwrap()
    }

    pub fn query_balance(&self, account_id: &String) -> i32 {
        let sql = String::from("select balance from daily_closing where account_id = ?1 order by date desc;");
        let mut stmt = self.con.prepare(&sql).unwrap();
        stmt.query_one([account_id], |row| {
            Ok(row.get(0)?)
        }).unwrap()
    }

    pub fn query_account_to_customer(&self, customer_id: &String) -> String {
        let sql = String::from("select account_id from account a inner join customer c on a.customer_id == c.customer_id where c.customer_id = ?1;");
        let mut stmt = self.con.prepare(&sql).unwrap();
        stmt.query_one([customer_id], |row| {
            Ok(row.get(0)?)
        }).unwrap()
    }
}