#include "undeniable_sig.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cassert>

using namespace std;
using namespace std::chrono;

// ============================================================================
// Pre-computed 512-bit test keys for fast testing
// These are valid safe prime parameters generated offline
// ============================================================================
UndeniableSignature::KeyPair getTestKeys() {
    UndeniableSignature::KeyPair keys;
    
    // 512-bit safe prime p = 2q + 1
    keys.pub.p = Integer("0xd4bcd52406f2bc89476146e54ecf8581e79269e39dea7bb4f69ec7eb6a9f5c57d1a7a77cd75969efb9a4f3f0c28a3d7f13a9e7b5c7d3f1e9a8b6c4d2e0f1a3b5c7h");
    keys.pub.q = Integer("0x6a5e6a9203795e44a3b0a372a767c2c0f3c934f1cef53dda7b4f63f5b54fae2be8d3d3be6bacb4f7dcd279f86145e9ebf89d4f3dae3e9f8f4d45b62696f08d1dae3h");
    
    // Generator g of order q
    keys.pub.g = Integer("0x4h");
    
    // Private key x (random in [1, q-1])
    keys.priv.x = Integer("0x2a3b4c5d6e7f8091a2b3c4d5e6f70819h");
    
    // Copy to private key struct
    keys.priv.p = keys.pub.p;
    keys.priv.q = keys.pub.q;
    keys.priv.g = keys.pub.g;
    
    // Compute public key y = g^x mod p
    keys.pub.y = a_exp_b_mod_c(keys.pub.g, keys.priv.x, keys.pub.p);
    
    return keys;
}

// Get a second set of test keys (for wrong-key tests)
UndeniableSignature::KeyPair getTestKeys2() {
    UndeniableSignature::KeyPair keys = getTestKeys();
    // Use different private key
    keys.priv.x = Integer("0x1122334455667788990011223344556677h");
    keys.pub.y = a_exp_b_mod_c(keys.pub.g, keys.priv.x, keys.pub.p);
    return keys;
}

// Helper to print test section headers
void printSection(const string& title) {
    cout << "\n" << string(60, '=') << endl;
    cout << "  " << title << endl;
    cout << string(60, '=') << endl;
}

// Helper to print Integer in readable format
void printInteger(const string& label, const Integer& value, int maxHexDigits = 32) {
    cout << label << ": ";
    
    ostringstream oss;
    oss << hex << value;
    string hexStr = oss.str();
    
    if (hexStr.length() > maxHexDigits) {
        cout << hexStr.substr(0, maxHexDigits/2) << "..." 
             << hexStr.substr(hexStr.length() - maxHexDigits/2);
    } else {
        cout << hexStr;
    }
    cout << " (" << dec << value.BitCount() << " bits)" << endl;
}

// Test 1: Basic happy path
void test1_BasicSignAndVerify() {
    printSection("TEST 1: Basic Sign and Interactive Verify");
    
    UndeniableSignature us;
    
    // Use pre-computed test keys for fast testing
    cout << "\n1. Loading pre-computed test keys..." << endl;
    auto keys = getTestKeys();
    cout << "   p bits: " << keys.pub.p.BitCount() << endl;
    
    // Sign message
    string message = "Hello, this is a test message for undeniable signatures!";
    cout << "\n2. Signing message: \"" << message << "\"" << endl;
    auto sig = us.sign(message, keys.priv);
    
    printInteger("   Signature", sig.s, 32);
    
    // Interactive verification
    cout << "\n3. Interactive Verification Protocol:" << endl;
    
    // Step 3a: Verifier creates challenge
    cout << "   [Verifier] Creating challenge..." << endl;
    auto challenge = us.createChallenge(message, sig, keys.pub);
    printInteger("   Challenge C", challenge.C, 32);
    
    // Step 3b: Signer responds
    cout << "   [Signer] Responding to challenge..." << endl;
    auto response = us.respondToChallenge(challenge, keys.priv);
    printInteger("   Response R", response.R, 32);
    
    // Step 3c: Verifier checks
    cout << "   [Verifier] Checking response..." << endl;
    bool valid = us.verifyResponse(challenge, response, sig, keys.pub);
    
    cout << "\n   OK! RESULT: Signature is " << (valid ? "VALID" : "INVALID") << endl;
    assert(valid && "Valid signature should verify successfully");
    
    cout << "\n   SUCCESS: Signature verified through interactive protocol!" << endl;
}

// Test 2: Invalid signature detection
void test2_InvalidSignature() {
    printSection("TEST 2: Detection of Invalid Signature");
    
    UndeniableSignature us;
    
    auto keys = getTestKeys();
    string message = "Original message";
    auto sig = us.sign(message, keys.priv);
    
    // Attempt 1: Wrong message
    cout << "\n1. Verifying signature with WRONG MESSAGE:" << endl;
    string wrongMessage = "Different message";
    bool result = us.interactiveVerify(wrongMessage, sig, keys.pub, keys.priv);
    cout << "   Result: " << (result ? "VALID" : "INVALID") << endl;
    assert(!result && "Wrong message should fail verification");
    cout << "   OK! Correctly rejected!" << endl;
    
    // Attempt 2: Forged signature
    cout << "\n2. Verifying FORGED SIGNATURE:" << endl;
    UndeniableSignature::Signature forgery;
    forgery.s = sig.s + 1;  // Simple forgery attempt
    result = us.interactiveVerify(message, forgery, keys.pub, keys.priv);
    cout << "   Result: " << (result ? "VALID" : "INVALID") << endl;
    assert(!result && "Forged signature should fail verification");
    cout << "   OK! Correctly rejected!" << endl;
    
    // Attempt 3: Wrong public key
    cout << "\n3. Verifying with WRONG PUBLIC KEY:" << endl;
    auto otherKeys = getTestKeys2();  // Use second pre-computed key set
    result = us.interactiveVerify(message, sig, otherKeys.pub, keys.priv);
    cout << "   Result: " << (result ? "VALID" : "INVALID") << endl;
    assert(!result && "Wrong public key should fail verification");
    cout << "   OK! Correctly rejected!" << endl;
}

// Test 3: Denial protocol
void test3_DenialProtocol() {
    printSection("TEST 3: Denial Protocol");
    
    UndeniableSignature us;
    
    auto keys = getTestKeys();
    string message = "Legitimate message";
    auto validSig = us.sign(message, keys.priv);
    
    cout << "\n1. Testing VALID signature (should not be deniable):" << endl;
    bool canDeny = us.denySignature(message, validSig, keys.priv, keys.pub);
    cout << "   Can deny valid signature? " << (canDeny ? "YES" : "NO") << endl;
    assert(!canDeny && "Should not be able to deny valid signature");
    cout << "   Correctly cannot deny valid signature!" << endl;
    
    cout << "\n2. Testing INVALID signature (should be deniable):" << endl;
    UndeniableSignature::Signature invalidSig;
    invalidSig.s = validSig.s + 42;  // Modified signature
    canDeny = us.denySignature(message, invalidSig, keys.priv, keys.pub);
    cout << "   Can deny invalid signature? " << (canDeny ? "YES" : "NO") << endl;
    assert(canDeny && "Should be able to deny invalid signature");
    cout << "   Successfully proved signature is invalid!" << endl;
    
    cout << "\n   The denial protocol allows signer to prove a signature" << endl;
    cout << "   is NOT theirs, while maintaining non-transferability." << endl;
}

// Test 4: Multiple messages with same key
void test4_MultipleMessages() {
    printSection("TEST 4: Multiple Messages with Same Keypair");
    
    UndeniableSignature us;
    
    cout << "\nUsing pre-computed test keys..." << endl;
    auto keys = getTestKeys();
    
    vector<string> messages = {
        "First message",
        "Second message",
        "Third message with more content",
        "Short",
        "A much longer message that contains significantly more text to demonstrate variable message length handling"
    };
    
    cout << "\nSigning and verifying " << messages.size() << " different messages:" << endl;
    
    for (size_t i = 0; i < messages.size(); i++) {
        cout << "\n" << (i+1) << ". Message: \"" << messages[i].substr(0, 40) 
             << (messages[i].length() > 40 ? "..." : "") << "\"" << endl;
        
        auto sig = us.sign(messages[i], keys.priv);
        bool valid = us.interactiveVerify(messages[i], sig, keys.pub, keys.priv);
        
        cout << "   Signature: " << hex << sig.s.GetBits(0, 64) << "..." << dec << endl;
        cout << "   Verification: " << (valid ? "VALID" : "INVALID") << endl;
        
        assert(valid && "All signatures should verify");
    }
    
    cout << "\n   SUCCESS: All messages signed and verified with same keypair!" << endl;
}

// Test 5: Key generation performance comparison
void test5_KeySizeComparison() {
    printSection("TEST 5: Key Generation Performance Comparison");
    
    UndeniableSignature us;
    string message = "Test message for performance comparison";
    
    cout << "\n=== FAST KEY GENERATION (RFC 3526 primes) ===" << endl;
    cout << "Using pre-computed safe primes from RFC 3526\n" << endl;
    
    vector<size_t> fastSizes = {1536, 2048, 3072, 4096};
    for (auto bitSize : fastSizes) {
        cout << bitSize << "-bit keys:" << endl;
        
        auto start = high_resolution_clock::now();
        auto keys = us.generateKeysFast(bitSize);
        auto keyGenTime = duration_cast<microseconds>(high_resolution_clock::now() - start);
        
        auto sig = us.sign(message, keys.priv);
        
        start = high_resolution_clock::now();
        bool valid = us.interactiveVerify(message, sig, keys.pub, keys.priv);
        auto verifyTime = duration_cast<microseconds>(high_resolution_clock::now() - start);
        
        cout << "  Key generation: " << keyGenTime.count() << " us (instant!)" << endl;
        cout << "  Verification:   " << verifyTime.count() << " us" << endl;
        cout << "  Valid:          " << (valid ? "YES" : "NO") << endl;
        cout << endl;
        
        assert(valid && "Signature should verify");
    }
    
    cout << "=== SLOW KEY GENERATION (random safe primes) ===" << endl;
    cout << "Generating new safe primes (very slow)\n" << endl;
    
    cout << "1024-bit keys (custom generation):" << endl;
    auto start = high_resolution_clock::now();
    auto keys = us.generateKeys(1024);
    auto keyGenTime = duration_cast<milliseconds>(high_resolution_clock::now() - start);
    
    auto sig = us.sign(message, keys.priv);
    bool valid = us.interactiveVerify(message, sig, keys.pub, keys.priv);
    
    cout << "  Key generation: " << keyGenTime.count() << " ms" << endl;
    cout << "  Valid:          " << (valid ? "YES" : "NO") << endl;
    
    assert(valid && "Signature should verify");
}

// Test 5: Serialization
void test5_Serialization() {
    printSection("TEST 5: Key and Signature Serialization");
    
    UndeniableSignature us;
    
    cout << "\n1. Using pre-computed test keys..." << endl;
    auto keys = getTestKeys();
    string message = "Message to be signed and serialized";
    auto sig = us.sign(message, keys.priv);
    
    // Save to files
    cout << "\n2. Saving to files..." << endl;
    keys.pub.save("public_key.txt");
    keys.priv.save("private_key.txt");
    sig.save("signature.txt");
    cout << "   ✓ Saved: public_key.txt, private_key.txt, signature.txt" << endl;
    
    // Load from files
    cout << "\n3. Loading from files..." << endl;
    UndeniableSignature::PublicKey loadedPub;
    UndeniableSignature::PrivateKey loadedPriv;
    UndeniableSignature::Signature loadedSig;
    
    loadedPub.load("public_key.txt");
    loadedPriv.load("private_key.txt");
    loadedSig.load("signature.txt");
    cout << "   ✓ Loaded successfully" << endl;
    
    // Verify with loaded data
    cout << "\n4. Verifying with loaded keys and signature..." << endl;
    bool valid = us.interactiveVerify(message, loadedSig, loadedPub, loadedPriv);
    cout << "   Result: " << (valid ? "VALID" : "INVALID") << endl;
    
    assert(valid && "Loaded signature should verify");
    cout << "\n   SUCCESS: Serialization and deserialization working!" << endl;
}

// Test 6: Protocol transcript
void test6_ProtocolTranscript() {
    printSection("TEST 6: Detailed Protocol Transcript");
    
    UndeniableSignature us;
    
    auto keys = getTestKeys();
    string message = "Message for protocol demonstration";
    
    cout << "\n=== SIGNATURE GENERATION ===" << endl;
    cout << "Message: \"" << message << "\"" << endl;
    
    auto sig = us.sign(message, keys.priv);
    printInteger("Signature s", sig.s);
    
    cout << "\n=== INTERACTIVE VERIFICATION PROTOCOL ===" << endl;
    cout << "\nRound 1:" << endl;
    
    // Create challenge
    cout << "  [Verifier → Signer] Creating challenge..." << endl;
    auto challenge1 = us.createChallenge(message, sig, keys.pub);
    printInteger("    Challenge C", challenge1.C);
    printInteger("    (Random a)", challenge1.a);
    printInteger("    (Random b)", challenge1.b);
    
    // Respond
    cout << "\n  [Signer → Verifier] Computing response..." << endl;
    auto response1 = us.respondToChallenge(challenge1, keys.priv);
    printInteger("    Response R", response1.R);
    
    // Verify
    cout << "\n  [Verifier] Checking if R = s^a * y^b mod p..." << endl;
    bool valid1 = us.verifyResponse(challenge1, response1, sig, keys.pub);
    cout << "    Result: " << (valid1 ? "VALID" : "INVALID") << endl;
    
    // Second round with different challenge
    cout << "\nRound 2 (different random values):" << endl;
    
    auto challenge2 = us.createChallenge(message, sig, keys.pub);
    printInteger("    Challenge C", challenge2.C);
    
    auto response2 = us.respondToChallenge(challenge2, keys.priv);
    printInteger("    Response R", response2.R);
    
    bool valid2 = us.verifyResponse(challenge2, response2, sig, keys.pub);
    cout << "    Result: " << (valid2 ? "VALID" : "INVALID") << endl;
    
    assert(valid1 && valid2);
    
    cout << "\n=== KEY PROPERTY: NON-TRANSFERABILITY ===" << endl;
    cout << "The verification transcript (C, R) does NOT prove validity" << endl;
    cout << "to third parties. Only through direct interaction with the" << endl;
    cout << "signer can one verify the signature. This prevents" << endl;
    cout << "unauthorized signature transfer or delegation." << endl;
}

// Test 7: Edge cases
void test7_EdgeCases() {
    printSection("TEST 7: Edge Cases");
    
    UndeniableSignature us;
    auto keys = getTestKeys();
    
    cout << "\n1. Very short message:" << endl;
    string shortMsg = "Hi";
    auto sig1 = us.sign(shortMsg, keys.priv);
    bool valid1 = us.interactiveVerify(shortMsg, sig1, keys.pub, keys.priv);
    cout << "   Message: \"" << shortMsg << "\"" << endl;
    cout << "   Result: " << (valid1 ? "VALID" : "INVALID") << endl;
    assert(valid1);
    
    cout << "\n2. Empty message:" << endl;
    string emptyMsg = "";
    auto sig2 = us.sign(emptyMsg, keys.priv);
    bool valid2 = us.interactiveVerify(emptyMsg, sig2, keys.pub, keys.priv);
    cout << "   Message: (empty string)" << endl;
    cout << "   Result: " << (valid2 ? "VALID" : "INVALID") << endl;
    assert(valid2);
    
    cout << "\n3. Long message (4KB):" << endl;
    string longMsg(4096, 'X');
    auto sig3 = us.sign(longMsg, keys.priv);
    bool valid3 = us.interactiveVerify(longMsg, sig3, keys.pub, keys.priv);
    cout << "   Message length: " << longMsg.length() << " bytes" << endl;
    cout << "   Result: " << (valid3 ? "VALID" : "INVALID") << endl;
    assert(valid3);
    
    cout << "\n4. Message with special characters:" << endl;
    string specialMsg = "Тест! @#$%^&*() 日本語 🔐";
    auto sig4 = us.sign(specialMsg, keys.priv);
    bool valid4 = us.interactiveVerify(specialMsg, sig4, keys.pub, keys.priv);
    cout << "   Message: \"" << specialMsg << "\"" << endl;
    cout << "   Result: " << (valid4 ? "VALID" : "INVALID") << endl;
    assert(valid4);
    
    cout << "\n   SUCCESS: All edge cases handled correctly!\n" << endl;
}

int main() {
    cout << "=============================================" << endl;
    cout << "  Undeniable Digital Signature - Test Suite  " << endl;
    cout << "   Chaum-van Antwerpen Protocol              " << endl;
    cout << "=============================================" << endl;
    
    try {
        test1_BasicSignAndVerify();
        test2_InvalidSignature();
        test3_DenialProtocol();
        test4_MultipleMessages();
        test5_Serialization();
        test6_ProtocolTranscript();
        test7_EdgeCases();
        
        printSection("ALL TESTS PASSED!");
        cout << "\nProtocol implementation verified" << endl;

        
        return 0;
        
    } catch (const exception& e) {
        cerr << "\nTEST FAILED: " << e.what() << endl;
        return 1;
    }
}
