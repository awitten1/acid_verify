#pragma once

#include "merklecpp/merklecpp.h"
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

inline std::string sha256(const void *data, size_t count) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(static_cast<const unsigned char*>(data), count, hash);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }
    return ss.str();
}

class DB {
    std::map<uint16_t, uint64_t> data_;
    merkle::Tree mt_;
    std::mutex m_;

    static inline std::string kv_to_hash_str(uint16_t k, uint64_t v) {
        uint8_t buf[10];
        std::memcpy(buf, &k, sizeof(k));
        std::memcpy(buf + sizeof(k), &v, sizeof(v));
        return sha256(buf, sizeof(buf));
    }

public:
    struct Proof {
        std::vector<std::shared_ptr<merkle::Tree::Path>> pre_state_paths;
        merkle::Tree::Hash old_root;
        merkle::Tree::Hash new_root;
    };

    class Txn {
        DB& db_;
        std::unique_ptr<std::lock_guard<std::mutex>> lg_;

        std::unordered_map<uint16_t, uint64_t> pending_writes_;
        std::unordered_set<uint16_t> performed_reads_;

    public:
        Txn(DB& db) : db_(db), lg_(new std::lock_guard<std::mutex>{db_.m_}) {}

        uint64_t Get(uint16_t k) {
            if (pending_writes_.find(k) != pending_writes_.end()) {
                return pending_writes_[k];
            }
            performed_reads_.insert(k);
            return db_.data_[k];
        }

        void Put(uint16_t k, uint64_t v) {
            pending_writes_[k] = v;
        }

        Proof Commit() {
            Proof proof;

            proof.old_root = db_.mt_.root();

            std::unordered_set<uint16_t> affected_indices = performed_reads_;
            for(auto const& [k, v] : pending_writes_) {
                affected_indices.insert(k);
            }

            for (uint16_t k : affected_indices) {
                proof.pre_state_paths.push_back(db_.mt_.path(k));
            }

            for (auto const& [k, v] : pending_writes_) {
                db_.data_[k] = v;
            }

            db_.RecomputeMerkleTree();

            proof.new_root = db_.mt_.root();

            return proof;
        }
    };

    Txn Begin() {
        return Txn(*this);
    }

    DB() {
        for (int i = 0; i <= std::numeric_limits<uint16_t>::max(); ++i) {
            data_[static_cast<uint16_t>(i)] = 0;
        }
        RecomputeMerkleTree();
    }

private:
    void RecomputeMerkleTree() {
        mt_ = merkle::Tree();

        for (int i = 0; i <= std::numeric_limits<uint16_t>::max(); ++i) {
            uint16_t k = static_cast<uint16_t>(i);
            uint64_t v = data_[k];
            mt_.insert(kv_to_hash_str(k, v));
        }
    }
};