use rs_merkle::{algorithms::Sha256, MerkleProof, MerkleTree};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

pub type Hash = [u8; 32];

pub fn hash_kv(key: &str, value: &str) -> Hash {
    let mut hasher = sha2::Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

pub struct Proof {
    pub old_root: Hash,
    pub new_root: Hash,
    pub total_leaves_old: usize,
    pub read_indices: Vec<usize>,
    pub read_proof: MerkleProof<Sha256>,
    pub total_leaves_new: usize,
    pub write_indices: Vec<usize>,
    pub write_proof: MerkleProof<Sha256>,
}

struct DbState {
    data: BTreeMap<String, String>,
    tree: MerkleTree<Sha256>,
}

impl DbState {
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
            .map(|(k, v)| hash_kv(k, v))
            .collect();
        self.tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    }
}

#[derive(Clone)]
pub struct VerifiableStore {
    state: Arc<RwLock<DbState>>,
}

impl VerifiableStore {
    pub fn new() -> Self {
        Self { state: Arc::new(RwLock::new(DbState::new())) }
    }

    pub fn begin(&self) -> Transaction<'_> {
        let guard = self.state.write().unwrap();
        let old_root = guard.tree.root().unwrap_or([0u8; 32]);

        Transaction {
            store_guard: guard,
            read_log: HashMap::new(),
            pending_writes: HashMap::new(),
            old_root,
        }
    }
}

pub struct Transaction<'a> {
    store_guard: RwLockWriteGuard<'a, DbState>,
    read_log: HashMap<String, String>,
    pending_writes: HashMap<String, String>,
    old_root: Hash,
}

impl<'a> Transaction<'a> {
    pub fn get(&mut self, key: &str) -> Option<String> {
        if let Some(val) = self.pending_writes.get(key) {
            return Some(val.clone());
        }

        let val = self.store_guard.data.get(key).cloned();

        if let Some(ref v) = val {
            self.read_log.insert(key.to_string(), v.clone());
        }
        val
    }

    pub fn put(&mut self, key: &str, value: &str) {
        self.pending_writes.insert(key.to_string(), value.to_string());
    }

    pub fn commit(mut self) -> Proof {
        let total_leaves_old = self.store_guard.data.len();
        let mut read_indices = Vec::new();

        for (i, (k, _)) in self.store_guard.data.iter().enumerate() {
            if self.read_log.contains_key(k) {
                read_indices.push(i);
            }
        }
        let read_proof = self.store_guard.tree.proof(&read_indices);

        for (k, v) in &self.pending_writes {
            self.store_guard.data.insert(k.clone(), v.clone());
        }

        self.store_guard.refresh_tree();
        let new_root = self.store_guard.tree.root().unwrap_or([0u8; 32]);
        let total_leaves_new = self.store_guard.data.len();

        let mut write_indices = Vec::new();
        for (i, (k, _)) in self.store_guard.data.iter().enumerate() {
            if self.pending_writes.contains_key(k) {
                write_indices.push(i);
            }
        }
        let write_proof = self.store_guard.tree.proof(&write_indices);

        Proof {
            old_root: self.old_root,
            new_root,
            total_leaves_old,
            read_indices,
            read_proof,
            total_leaves_new,
            write_indices,
            write_proof,
        }
    }
}

pub fn verify_transaction(
    proof: &Proof,
    reads: &HashMap<String, String>,
    writes: &HashMap<String, String>,
) -> bool {
    let mut sorted_reads: Vec<(&String, &String)> = reads.iter().collect();
    sorted_reads.sort_by_key(|(k, _)| *k);

    let read_leaves: Vec<Hash> = sorted_reads.iter()
        .map(|(k, v)| hash_kv(k, v))
        .collect();

    let reads_ok = proof.read_proof.verify(
        proof.old_root,
        &proof.read_indices,
        &read_leaves,
        proof.total_leaves_old,
    );

    let mut sorted_writes: Vec<(&String, &String)> = writes.iter().collect();
    sorted_writes.sort_by_key(|(k, _)| *k);

    let write_leaves: Vec<Hash> = sorted_writes.iter()
        .map(|(k, v)| hash_kv(k, v))
        .collect();

    let writes_ok = proof.write_proof.verify(
        proof.new_root,
        &proof.write_indices,
        &write_leaves,
        proof.total_leaves_new,
    );

    reads_ok && writes_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_and_write_proofs() {
        let store = VerifiableStore::new();

        let mut t0 = store.begin();
        t0.put("alice", "100");
        t0.commit();

        let mut txn = store.begin();

        let val = txn.get("alice").expect("Alice should exist");
        assert_eq!(val, "100");

        txn.put("bob", "50");

        let proof = txn.commit();

        let mut expected_reads = HashMap::new();
        expected_reads.insert("alice".to_string(), "100".to_string());

        let mut expected_writes = HashMap::new();
        expected_writes.insert("bob".to_string(), "50".to_string());

        let valid = verify_transaction(&proof, &expected_reads, &expected_writes);
        assert!(valid);
    }

    #[test]
    fn test_stale_read_attack() {
        let store = VerifiableStore::new();

        let mut t0 = store.begin();
        t0.put("x", "10");
        t0.commit();

        let mut txn = store.begin();
        txn.get("x");
        let proof = txn.commit();

        let mut fake_reads = HashMap::new();
        fake_reads.insert("x".to_string(), "20".to_string());

        let valid = verify_transaction(&proof, &fake_reads, &HashMap::new());
        assert!(!valid);
    }
}