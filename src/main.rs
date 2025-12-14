

use txn_verify::VerifiableDB;
use rand::distr::{Alphanumeric, SampleString};

fn main() {
  let db = VerifiableDB::new();
  for n in 1..100000 {
    if n % 100 == 0 {
      println!("{} asdf", n);
    }
    let mut txn = db.begin();
    for _ in 1..100 {
      txn.put(&Alphanumeric.sample_string(&mut rand::rng(), 2), "b");
    }
    txn.commit();
  }
}
