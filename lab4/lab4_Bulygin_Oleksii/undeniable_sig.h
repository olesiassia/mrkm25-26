#ifndef UNDENIABLE_SIG_H
#define UNDENIABLE_SIG_H

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>
#include <string>
#include <vector>

using namespace CryptoPP;

/**
 * Undeniable Digital Signature Implementation
 * Based on Chaum-van Antwerpen protocol using discrete logarithms
 * 
 * Key property: Verification requires interaction with signer
 * Signature cannot be verified without signer's cooperation
 */
class UndeniableSignature {
public:
    // Key structures
    struct PublicKey {
        Integer p;  // Prime modulus (safe prime: p = 2q + 1)
        Integer q;  // Prime order of subgroup
        Integer g;  // Generator of subgroup of order q
        Integer y;  // Public key: y = g^x mod p
        
        void save(const std::string& filename) const;
        void load(const std::string& filename);
    };
    
    struct PrivateKey {
        Integer p;  // Prime modulus
        Integer q;  // Prime order of subgroup
        Integer g;  // Generator
        Integer x;  // Private exponent
        
        void save(const std::string& filename) const;
        void load(const std::string& filename);
    };
    
    struct KeyPair {
        PublicKey pub;
        PrivateKey priv;
    };
    
    struct Signature {
        Integer s;  // Signature value: s = m^x mod p
        
        void save(const std::string& filename) const;
        void load(const std::string& filename);
    };
    
    struct VerificationChallenge {
        Integer C;  // Challenge: C = m^a * g^b mod p
        Integer a;  // Random value (kept by verifier)
        Integer b;  // Random value (kept by verifier)
    };
    
    struct VerificationResponse {
        Integer R;  // Response: R = C^x mod p
    };

    // Constructor
    UndeniableSignature();
    
    // Key generation
    KeyPair generateKeys(size_t bitSize = 2048);
    
    // Fast key generation using RFC 3526 pre-computed safe primes
    // Supported sizes: 1536, 2048, 3072, 4096
    KeyPair generateKeysFast(size_t bitSize = 2048);
    
    // Signing
    Signature sign(const std::string& message, const PrivateKey& sk);
    Signature sign(const Integer& messageHash, const PrivateKey& sk);
    
    // Interactive verification protocol
    VerificationChallenge createChallenge(
        const std::string& message,
        const Signature& sig,
        const PublicKey& pk
    );
    
    VerificationResponse respondToChallenge(
        const VerificationChallenge& challenge,
        const PrivateKey& sk
    );
    
    bool verifyResponse(
        const VerificationChallenge& challenge,
        const VerificationResponse& response,
        const Signature& sig,
        const PublicKey& pk
    );
    
    // Complete verification (combines all steps)
    bool interactiveVerify(
        const std::string& message,
        const Signature& sig,
        const PublicKey& pk,
        const PrivateKey& sk
    );
    
    // Denial protocol - prove signature is invalid
    bool denySignature(
        const std::string& message,
        const Signature& sig,
        const PrivateKey& sk,
        const PublicKey& pk
    );
    
    // Utility functions
    Integer hashMessage(const std::string& message) const;
    
private:
    AutoSeededRandomPool rng_;
    
    // Helper: Generate safe prime p and generator g
    void generatePrimeAndGenerator(Integer& p, Integer& q, Integer& g, size_t bitSize);
    
    // Helper: Get RFC 3526 pre-computed parameters
    void getRFC3526Parameters(size_t bitSize, Integer& p, Integer& q, Integer& g);
};

#endif // UNDENIABLE_SIG_H
