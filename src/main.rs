

use std::time::Instant;

use txn_verify::VerifiableDB;
use rand::distr::{Alphanumeric, SampleString};

fn run_experiments(verify: bool, num_txns: u32) {
  let db = VerifiableDB::new(verify);
  for i in 1..num_txns {
    if i % 1000 == 0 {
      println!("{}", i)
    }
    let mut txn = db.begin();
    for _ in 1..100 {
      txn.put(&Alphanumeric.sample_string(&mut rand::rng(), 4), "b");
    }
    txn.commit();
  }
}

fn main() {
  let mut now = Instant::now();
  let num_txns = 10000;
  run_experiments(true, num_txns);
  let mut elapsed = now.elapsed();
  println!("{}ms to run {} verified txns", elapsed.as_millis(), num_txns);

  now = Instant::now();
  run_experiments(false, num_txns);
  elapsed = now.elapsed();
  println!("{}ms to run {} unverified txns", elapsed.as_millis(), num_txns);
}
