

use std::time::Instant;

use txn_verify::VerifiableDB;
use rand::prelude::*;

fn run_experiments(verify: bool, num_txns: u32, key_space_size: u64) -> usize {
  let mut rng = rand::rng();

  let db = VerifiableDB::new(verify);
  for _ in 1..num_txns {
    // if i % 1000 == 0 {
    //   println!("{}", i)
    // }
    let mut txn = db.begin();
    for _ in 1..100 {
      txn.put(rng.random::<u64>() % key_space_size, rng.random::<u64>() % key_space_size);
    }
    txn.commit();
  }
  db.get_db_size()
}

fn main() {
  let mut now = Instant::now();
  let num_txns = 10000;
  println!("elapsed_ms,num_keys,num_txns,verified");
  for keyspace_size in 1..200 {
    let ksize = 10*keyspace_size;
    let mut dbsize = run_experiments(true, num_txns, ksize);
    let mut elapsed = now.elapsed();
    println!("{},{},{},true", elapsed.as_millis(),dbsize,num_txns);

    now = Instant::now();
    dbsize = run_experiments(false, num_txns, ksize);
    elapsed = now.elapsed();
    println!("{},{},{},false", elapsed.as_millis(),dbsize,num_txns);
  }
}
