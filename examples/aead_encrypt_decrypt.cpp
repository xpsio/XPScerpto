import xps.crypto.api;

#include <vector>
#include <cstdint>
#include <iostream>

using namespace xps::crypto;

int main() {
    std::vector<std::uint8_t> data = {1,2,3,4,5};
    Bytes key = api::random_bytes(32); // AES-256
    Bytes aad;                         // optional

    auto sealed = api::aead::encrypt(api::AEAD::AES_GCM, key, data, aad);
    auto plain  = api::aead::decrypt(api::AEAD::AES_GCM, key,
                                     sealed.nonce, sealed.ciphertext, sealed.tag, aad);

    std::cout << "AEAD roundtrip bytes: " << plain.size() << "\n";
    secure_wipe(key);
    return 0;
}
