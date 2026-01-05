#include "undeniable_sig.h"
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <fstream>
#include <iostream>
#include <iomanip>

UndeniableSignature::UndeniableSignature() {
    // Initialize random number generator
}

void UndeniableSignature::generatePrimeAndGenerator(Integer& p, Integer& q, Integer& g, size_t bitSize) {
    // Generate safe prime: p = 2q + 1 where both p and q are prime
    // This ensures the multiplicative group has large prime order
    
    std::cout << "Generating " << bitSize << "-bit safe prime (this may take a while)..." << std::endl;
    
    do {
        // Generate random number of correct bit size
        q.Randomize(rng_, bitSize - 1);
        
        // Set the high bit to ensure it's the right size
        q.SetBit(bitSize - 2);
        
        // Make it odd (primes > 2 must be odd)
        q.SetBit(0);
        
        // Test for primality
        if (!IsPrime(q)) continue;
        
        // Check if p = 2q + 1 is also prime
        p = 2 * q + 1;
        
    } while (!IsPrime(p));
    
    std::cout << "Safe prime generated. Finding generator..." << std::endl;
    
    // Find generator g of order q in Z*_p
    // g should generate the subgroup of order q (quadratic residues)
    Integer h;
    do {
        h.Randomize(rng_, Integer::Two(), p - 1);
        g = a_exp_b_mod_c(h, Integer::Two(), p);
    } while (g == Integer::One());
    
    // Validate generator: g != 1 and g^q = 1 mod p
    Integer gq = a_exp_b_mod_c(g, q, p);
    if (gq != Integer::One()) {
        throw std::runtime_error("Generator validation failed: g^q != 1 mod p");
    }
    
    std::cout << "Generator found and validated." << std::endl;
}

// RFC 3526 - More Modular Exponential (MODP) Diffie-Hellman groups
// These are well-audited safe primes used in TLS, IPsec, SSH
void UndeniableSignature::getRFC3526Parameters(size_t bitSize, Integer& p, Integer& q, Integer& g) {
    // All groups use g = 2
    g = Integer::Two();
    
    if (bitSize == 1536) {
        // 1536-bit MODP Group (Group 5)
        p = Integer("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF");
    } else if (bitSize == 2048) {
        // 2048-bit MODP Group (Group 14)
        p = Integer("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    "15728E5A8AACAA68FFFFFFFFFFFFFFFF");
    } else if (bitSize == 3072) {
        // 3072-bit MODP Group (Group 15)
        p = Integer("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");
    } else if (bitSize == 4096) {
        // 4096-bit MODP Group (Group 16)
        p = Integer("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                    "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
                    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
                    "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
                    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
                    "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
                    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
                    "FFFFFFFFFFFFFFFF");
    } else {
        throw std::runtime_error("Unsupported bit size for RFC 3526. Use 1536, 2048, 3072, or 4096.");
    }
    
    // For safe primes p = 2q + 1, so q = (p - 1) / 2
    q = (p - 1) / 2;
}

UndeniableSignature::KeyPair UndeniableSignature::generateKeysFast(size_t bitSize) {
    KeyPair keys;
    
    std::cout << "Using RFC 3526 " << bitSize << "-bit MODP parameters..." << std::endl;
    
    // Get pre-computed safe prime parameters
    getRFC3526Parameters(bitSize, keys.pub.p, keys.pub.q, keys.pub.g);
    keys.priv.p = keys.pub.p;
    keys.priv.q = keys.pub.q;
    keys.priv.g = keys.pub.g;
    
    // Generate private key x (random in [1, q-1])
    keys.priv.x.Randomize(rng_, Integer::One(), keys.pub.q - 1);
    
    // Compute public key y = g^x mod p
    keys.pub.y = a_exp_b_mod_c(keys.pub.g, keys.priv.x, keys.pub.p);
    
    std::cout << "Key generation complete (fast mode)." << std::endl;
    std::cout << "  p bits: " << keys.pub.p.BitCount() << std::endl;
    std::cout << "  q bits: " << keys.pub.q.BitCount() << std::endl;
    std::cout << "  x bits: " << keys.priv.x.BitCount() << std::endl;
    
    return keys;
}

UndeniableSignature::KeyPair UndeniableSignature::generateKeys(size_t bitSize) {
    KeyPair keys;
    
    // Generate p, q, g
    generatePrimeAndGenerator(keys.pub.p, keys.pub.q, keys.pub.g, bitSize);
    keys.priv.p = keys.pub.p;
    keys.priv.q = keys.pub.q;
    keys.priv.g = keys.pub.g;
    
    // Generate private key x (random in [1, q-1])
    keys.priv.x.Randomize(rng_, Integer::One(), keys.pub.q - 1);
    
    // Compute public key y = g^x mod p
    keys.pub.y = a_exp_b_mod_c(keys.pub.g, keys.priv.x, keys.pub.p);
    
    std::cout << "Key generation complete." << std::endl;
    std::cout << "  p bits: " << keys.pub.p.BitCount() << std::endl;
    std::cout << "  q bits: " << keys.pub.q.BitCount() << std::endl;
    std::cout << "  x bits: " << keys.priv.x.BitCount() << std::endl;
    
    return keys;
}

Integer UndeniableSignature::hashMessage(const std::string& message) const {
    // Hash message to integer using SHA-256
    SHA256 hash;
    byte digest[SHA256::DIGESTSIZE];
    
    hash.CalculateDigest(digest, (const byte*)message.data(), message.size());
    
    // Convert hash to Integer
    Integer result;
    result.Decode(digest, SHA256::DIGESTSIZE);
    
    return result;
}

UndeniableSignature::Signature UndeniableSignature::sign(
    const std::string& message,
    const PrivateKey& sk
) {
    Integer messageHash = hashMessage(message);
    return sign(messageHash, sk);
}

UndeniableSignature::Signature UndeniableSignature::sign(
    const Integer& messageHash,
    const PrivateKey& sk
) {
    Signature sig;
    
    // Ensure message is in valid range and map to group element
    // Reduce hash modulo q first to avoid unnecessarily large exponents
    // Use m = g^(H(message) mod q) mod p to ensure it's in the right subgroup
    Integer reducedHash = messageHash % sk.q;
    if (reducedHash == Integer::Zero()) {
        reducedHash = Integer::One();  // Avoid identity element
    }
    Integer m = a_exp_b_mod_c(sk.g, reducedHash, sk.p);
    
    // Compute signature: s = m^x mod p
    sig.s = a_exp_b_mod_c(m, sk.x, sk.p);
    
    return sig;
}

UndeniableSignature::VerificationChallenge UndeniableSignature::createChallenge(
    const std::string& message,
    const Signature& sig,
    const PublicKey& pk
) {
    VerificationChallenge challenge;
    
    // Hash and map message to group element (with reduction mod q)
    Integer messageHash = hashMessage(message);
    Integer reducedHash = messageHash % pk.q;
    if (reducedHash == Integer::Zero()) {
        reducedHash = Integer::One();
    }
    Integer m = a_exp_b_mod_c(pk.g, reducedHash, pk.p);
    
    // Generate random a, b for challenge in [1, q-1]
    challenge.a.Randomize(rng_, Integer::One(), pk.q - 1);
    challenge.b.Randomize(rng_, Integer::One(), pk.q - 1);
    
    // Compute C = m^a * g^b mod p
    Integer ma = a_exp_b_mod_c(m, challenge.a, pk.p);
    Integer gb = a_exp_b_mod_c(pk.g, challenge.b, pk.p);
    challenge.C = a_times_b_mod_c(ma, gb, pk.p);
    
    return challenge;
}

UndeniableSignature::VerificationResponse UndeniableSignature::respondToChallenge(
    const VerificationChallenge& challenge,
    const PrivateKey& sk
) {
    VerificationResponse response;
    
    // Compute R = C^x mod p
    response.R = a_exp_b_mod_c(challenge.C, sk.x, sk.p);
    
    return response;
}

bool UndeniableSignature::verifyResponse(
    const VerificationChallenge& challenge,
    const VerificationResponse& response,
    const Signature& sig,
    const PublicKey& pk
) {
    // Check: R ?= s^a * y^b mod p
    // This verifies that log_m(s) = log_g(y) = x
    
    Integer sa = a_exp_b_mod_c(sig.s, challenge.a, pk.p);
    Integer yb = a_exp_b_mod_c(pk.y, challenge.b, pk.p);
    Integer expected = a_times_b_mod_c(sa, yb, pk.p);
    
    return response.R == expected;
}

bool UndeniableSignature::interactiveVerify(
    const std::string& message,
    const Signature& sig,
    const PublicKey& pk,
    const PrivateKey& sk
) {
    // Complete verification protocol
    // 1. Verifier creates challenge
    auto challenge = createChallenge(message, sig, pk);
    
    // 2. Signer responds
    auto response = respondToChallenge(challenge, sk);
    
    // 3. Verifier checks response
    return verifyResponse(challenge, response, sig, pk);
}

bool UndeniableSignature::denySignature(
    const std::string& message,
    const Signature& sig,
    const PrivateKey& sk,
    const PublicKey& pk
) {
    // Chaum-van Antwerpen Denial Protocol
    // Prove that s != m^x mod p using zero-knowledge proof
    // 
    // Protocol:
    // 1. Verifier sends random challenges (a1, b1) and (a2, b2)
    // 2. Signer computes responses for both
    // 3. If signature is invalid, signer can prove it by showing
    //    that the DL relationship doesn't hold
    
    const int NUM_ROUNDS = 4;  // Multiple rounds for statistical soundness
    int failedRounds = 0;
    
    // Hash and map message to group element
    Integer messageHash = hashMessage(message);
    Integer reducedHash = messageHash % pk.q;
    if (reducedHash == Integer::Zero()) {
        reducedHash = Integer::One();
    }
    Integer m = a_exp_b_mod_c(pk.g, reducedHash, pk.p);
    
    // Compute what the correct signature should be
    Integer correctSig = a_exp_b_mod_c(m, sk.x, sk.p);
    
    // If signature matches, cannot deny
    if (sig.s == correctSig) {
        return false;  // Valid signature - cannot deny
    }
    
    // Run multiple rounds of the denial protocol
    for (int round = 0; round < NUM_ROUNDS; round++) {
        // Generate two independent challenges
        Integer a1, b1, a2, b2;
        a1.Randomize(rng_, Integer::One(), pk.q - 1);
        b1.Randomize(rng_, Integer::One(), pk.q - 1);
        a2.Randomize(rng_, Integer::One(), pk.q - 1);
        b2.Randomize(rng_, Integer::One(), pk.q - 1);
        
        // Compute C1 = m^a1 * g^b1 mod p
        Integer ma1 = a_exp_b_mod_c(m, a1, pk.p);
        Integer gb1 = a_exp_b_mod_c(pk.g, b1, pk.p);
        Integer C1 = a_times_b_mod_c(ma1, gb1, pk.p);
        
        // Compute C2 = m^a2 * g^b2 mod p  
        Integer ma2 = a_exp_b_mod_c(m, a2, pk.p);
        Integer gb2 = a_exp_b_mod_c(pk.g, b2, pk.p);
        Integer C2 = a_times_b_mod_c(ma2, gb2, pk.p);
        
        // Signer computes responses R1 = C1^x, R2 = C2^x
        Integer R1 = a_exp_b_mod_c(C1, sk.x, pk.p);
        Integer R2 = a_exp_b_mod_c(C2, sk.x, pk.p);
        
        // Expected values if signature were valid: s^ai * y^bi
        Integer expected1 = a_times_b_mod_c(
            a_exp_b_mod_c(sig.s, a1, pk.p),
            a_exp_b_mod_c(pk.y, b1, pk.p),
            pk.p
        );
        Integer expected2 = a_times_b_mod_c(
            a_exp_b_mod_c(sig.s, a2, pk.p),
            a_exp_b_mod_c(pk.y, b2, pk.p),
            pk.p
        );
        
        // For invalid signature, R != expected
        // But we need to prove this consistently
        bool match1 = (R1 == expected1);
        bool match2 = (R2 == expected2);
        
        // Both should fail for invalid signature
        if (!match1 && !match2) {
            failedRounds++;
        }
    }
    
    // Signature is provably invalid if all rounds failed consistently
    return (failedRounds == NUM_ROUNDS);
}

// Serialization methods
void UndeniableSignature::PublicKey::save(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for writing: " + filename);
    }
    
    file << "p=" << std::hex << p << std::endl;
    file << "q=" << std::hex << q << std::endl;
    file << "g=" << std::hex << g << std::endl;
    file << "y=" << std::hex << y << std::endl;
    file.close();
}

void UndeniableSignature::PublicKey::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for reading: " + filename);
    }
    
    std::string line, key, value;
    while (std::getline(file, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            key = line.substr(0, pos);
            value = line.substr(pos + 1);
            
            if (key == "p") p = Integer((std::string("0x") + value).c_str());
            else if (key == "q") q = Integer((std::string("0x") + value).c_str());
            else if (key == "g") g = Integer((std::string("0x") + value).c_str());
            else if (key == "y") y = Integer((std::string("0x") + value).c_str());
        }
    }
    file.close();
}

void UndeniableSignature::PrivateKey::save(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for writing: " + filename);
    }
    
    file << "p=" << std::hex << p << std::endl;
    file << "q=" << std::hex << q << std::endl;
    file << "g=" << std::hex << g << std::endl;
    file << "x=" << std::hex << x << std::endl;
    file.close();
}

void UndeniableSignature::PrivateKey::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for reading: " + filename);
    }
    
    std::string line, key, value;
    while (std::getline(file, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            key = line.substr(0, pos);
            value = line.substr(pos + 1);
            
            if (key == "p") p = Integer((std::string("0x") + value).c_str());
            else if (key == "q") q = Integer((std::string("0x") + value).c_str());
            else if (key == "g") g = Integer((std::string("0x") + value).c_str());
            else if (key == "x") x = Integer((std::string("0x") + value).c_str());
        }
    }
    file.close();
}

void UndeniableSignature::Signature::save(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for writing: " + filename);
    }
    
    file << "s=" << std::hex << s << std::endl;
    file.close();
}

void UndeniableSignature::Signature::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for reading: " + filename);
    }
    
    std::string line;
    if (std::getline(file, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string value = line.substr(pos + 1);
            s = Integer((std::string("0x") + value).c_str());
        }
    }
    file.close();
}