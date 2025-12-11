use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Default)]
pub struct Database {
    db: Mutex<HashMap<u64, u64>>,
}

impl Database {
    pub fn create_txn<'a>(&'a self) -> Txn<'a> {
        Txn {
            db_guard: self.db.lock().unwrap(),
        }
    }
}

pub struct Txn<'a> {
    db_guard: MutexGuard<'a, HashMap<u64, u64>>,
}

impl<'a> Txn<'a> {
    pub fn get(&self, key: u64) -> Option<u64> {
        self.db_guard.get(&key).copied()
    }

    pub fn put(&mut self, key: u64, value: u64) {
        self.db_guard.insert(key, value);
    }

    pub fn commit(self) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use std::sync::Arc;

    #[test]
    fn test_blocking_behavior() {
        let db = Arc::new(Database::default());
        let db_clone = db.clone();

        let handle = thread::spawn(move || {
            let mut txn = db_clone.create_txn();
            txn.put(1, 100);
            thread::sleep(Duration::from_millis(100));
            txn.commit(); // Lock released here
        });

        thread::sleep(Duration::from_millis(10));

        let txn_main = db.create_txn();
        assert_eq!(txn_main.get(1), Some(100));

        handle.join().unwrap();
    }
}