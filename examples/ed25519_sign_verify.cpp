import xps.crypto.api;

#include <vector>
#include <cstdint>
#include <iostream>

using namespace xps::crypto;

int main() {
    std::vector<std::uint8_t> message = {10, 20, 30};

    auto [pk, sk] = api::ed25519::generate_keypair();
    auto sig = api::ed25519::sign(sk, message);
    bool ok  = api::ed25519::verify(pk, message, sig);

    std::cout << "Ed25519 verify: " << (ok ? "OK" : "FAIL") << "\n";
    secure_wipe(sk);
    return ok ? 0 : 1;
}
