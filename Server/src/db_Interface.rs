use rusqlite::{Connection};

pub struct DB_Interface{
    con: Connection,
}

pub struct QueryResCustomer {
    pub customer_id: String,
    pub password: String,
}

impl DB_Interface {
    pub fn new(url: String) -> rusqlite::Result<DB_Interface> {
        let is_initiallized = std::fs::exists(&url).unwrap();
        let con = Connection::open(&url)?;
        let db = DB_Interface {
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

    pub fn query_customer(&self, attr: String, value: &String) -> QueryResCustomer {
        let mut sql = String::from("select customer_id, password from customer where ");
        sql.push_str(&attr);
        sql.push_str(" = '");
        sql.push_str(value);
        sql.push_str("';");
        let mut stmt = self.con.prepare(&sql).unwrap();

        stmt.query_one([], |row| {
            Ok(QueryResCustomer {
                customer_id: row.get(0)?,
                password: row.get(1)?
            })
        }).unwrap()
    }
}