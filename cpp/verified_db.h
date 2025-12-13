#pragma once

#include <openssl/sha.h>

#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

inline std::string sha256(const unsigned char *buf, size_t count) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf, count, hash);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    return ss.str();
}