use rs_merkle::{algorithms::Sha256, MerkleProof, MerkleTree};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

pub type Hash = [u8; 32];

pub fn hash_kv(key: u64, value: u64) -> Hash {
    let mut hasher = sha2::Sha256::new();
    hasher.update(key.to_be_bytes());
    hasher.update(value.to_be_bytes());
    hasher.finalize().into()
}

pub struct Proof {
    pub old_root: Hash,
    pub new_root: Hash,
    pub total_leaves_old: usize,
    pub affected_indices: Vec<usize>,
    pub pre_state_proof: MerkleProof<Sha256>,
}

struct DB {
    data: BTreeMap<u64, u64>,
    tree: MerkleTree<Sha256>,
}

impl DB {
    fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            tree: MerkleTree::<Sha256>::new(),
        }
    }

    fn refresh_tree(&mut self) {
        if self.data.is_empty() {
            self.tree = MerkleTree::<Sha256>::new();
            return;
        }
        let leaves: Vec<Hash> = self.data.iter()
            .map(|(k, v)| hash_kv(*k, *v))
            .collect();
        self.tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    }

    fn get_db_size(&self) -> usize {
        self.data.len()
    }
}

#[derive(Clone)]
pub struct VerifiableDB {
    state: Arc<RwLock<DB>>,
    verify_txn: bool,
}

impl VerifiableDB {
    pub fn new(verify_txn: bool) -> Self {
        Self { state: Arc::new(RwLock::new(DB::new())), verify_txn }
    }

    pub fn begin(&self) -> Transaction<'_> {
        let guard = self.state.write().unwrap();
        let old_root = guard.tree.root().unwrap_or([0u8; 32]);

        Transaction {
            guard: guard,
            performed_reads: HashMap::new(),
            pending_writes: HashMap::new(),
            old_root,
            verify_txn: self.verify_txn,
        }
    }

    pub fn get_db_size(&self) -> usize {
        self.state.read().unwrap().get_db_size()
    }
}

pub struct Transaction<'a> {
    guard: RwLockWriteGuard<'a, DB>,
    performed_reads: HashMap<u64, u64>,
    pending_writes: HashMap<u64, u64>,
    old_root: Hash,
    verify_txn: bool,
}

impl<'a> Transaction<'a> {
    pub fn get(&mut self, key: u64) -> Option<u64> {
        if let Some(val) = self.pending_writes.get(&key) {
            return Some(*val);
        }

        let val = self.guard.data.get(&key).copied();
        if let Some(v) = val {
            self.performed_reads.insert(key, v);
        }
        val
    }

    pub fn put(&mut self, key: u64, value: u64) {
        self.pending_writes.insert(key, value);
    }

    pub fn commit(mut self) -> Option<Proof> {
        if self.verify_txn {
            let total_leaves_old = self.guard.data.len();

            let mut affected_keys = HashSet::new();
            for k in self.performed_reads.keys() {
                affected_keys.insert(*k);
            }
            for k in self.pending_writes.keys() {
                affected_keys.insert(*k);
            }

            let mut affected_indices = Vec::new();
            for (i, (k, _)) in self.guard.data.iter().enumerate() {
                if affected_keys.contains(k) {
                    affected_indices.push(i);
                }
            }

            let pre_state_proof = self.guard.tree.proof(&affected_indices);

            for (k, v) in &self.pending_writes {
                self.guard.data.insert(*k, *v);
            }

            self.guard.refresh_tree();
            let new_root = self.guard.tree.root().unwrap_or([0u8; 32]);
            Some(Proof {
                old_root: self.old_root,
                new_root,
                total_leaves_old,
                affected_indices,
                pre_state_proof,
            })
        } else {
            for (k, v) in &self.pending_writes {
                self.guard.data.insert(*k, *v);
            }
            None
        }
    }
}

pub fn verify_secure_update(
    proof: &Proof,
    old_state: &HashMap<u64, u64>,
    new_state: &HashMap<u64, u64>,
) -> bool {
    let mut sorted_keys: Vec<&u64> = old_state.keys().collect();
    sorted_keys.sort();

    let old_leaves: Vec<Hash> = sorted_keys.iter()
        .map(|k| {
            let val = old_state.get(*k).expect("Key missing in old state");
            hash_kv(**k, *val)
        })
        .collect();

    let read_ok = proof.pre_state_proof.verify(
        proof.old_root,
        &proof.affected_indices,
        &old_leaves,
        proof.total_leaves_old,
    );

    if !read_ok {
        println!("Security Alert: Pre-state proof invalid.");
        return false;
    }

    let new_leaves: Vec<Hash> = sorted_keys.iter()
        .map(|k| {
            let val = new_state.get(*k).or_else(|| old_state.get(*k)).unwrap();
            hash_kv(**k, *val)
        })
        .collect();

    let calculated_root_res = proof.pre_state_proof.root(
        &proof.affected_indices,
        &new_leaves,
        proof.total_leaves_old
    );

    let calculated_root = match calculated_root_res {
        Ok(r) => r,
        Err(_) => return false,
    };

    calculated_root == proof.new_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_update_transition() {
        let store = VerifiableDB::new(true);

        // t0: Insert 1 -> 100, 2 -> 50
        let mut t0 = store.begin();
        t0.put(1, 100);
        t0.put(2, 50);
        t0.commit();

        let mut txn = store.begin();

        let old_val = txn.get(1).expect("Key 1 should exist");
        assert_eq!(old_val, 100);

        txn.put(1, 200);
        let proof = txn.commit().unwrap();

        let mut old_state = HashMap::new();
        old_state.insert(1, 100);

        let mut new_state = HashMap::new();
        new_state.insert(1, 200);

        let is_valid = verify_secure_update(
            &proof,
            &old_state,
            &new_state
        );

        assert!(is_valid, "The derived root should match the server's new root");
    }

    #[test]
    fn test_blind_write_is_covered() {
        let store = VerifiableDB::new(true);

        // t0: Insert 10 -> 10, 20 -> 20
        let mut t0 = store.begin();
        t0.put(10, 10);
        t0.put(20, 20);
        t0.commit();

        let mut txn = store.begin();
        txn.put(10, 99);
        let proof = txn.commit().unwrap();

        let mut old_state = HashMap::new();
        old_state.insert(10, 10);

        let mut new_state = HashMap::new();
        new_state.insert(10, 99);

        let is_valid = verify_secure_update(&proof, &old_state, &new_state);
        assert!(is_valid);
    }
}