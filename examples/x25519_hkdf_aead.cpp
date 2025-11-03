import xps.crypto.api;

#include <vector>
#include <cstdint>
#include <iostream>

using namespace xps::crypto;

int main() {
    auto [c_pk, c_sk] = api::x25519::generate_keypair();
    auto [s_pk, s_sk] = api::x25519::generate_keypair();

    auto client_shared = api::x25519::derive_shared(c_sk, s_pk);
    auto server_shared = api::x25519::derive_shared(s_sk, c_pk);

    Bytes info = {0,1,2,3}; // transcript/context
    auto keys_c = api::hkdf::expand(client_shared, info, 64);
    auto keys_s = api::hkdf::expand(server_shared, info, 64);

    auto ctx_c = api::aead::make(api::AEAD::AES_GCM, keys_c.enc, keys_c.iv);
    auto ctx_s = api::aead::make(api::AEAD::AES_GCM, keys_s.enc, keys_s.iv);

    std::vector<std::uint8_t> req = {42, 7, 9};
    auto sealed = api::aead::seal(ctx_c, req, Bytes{});
    auto plain  = api::aead::open(ctx_s, sealed.ciphertext, sealed.tag, Bytes{}, sealed.nonce);

    std::cout << "Session decrypt len: " << plain.size() << "\n";
    secure_wipe(c_sk); secure_wipe(s_sk);
    return 0;
}
