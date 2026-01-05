/**
 * Лабораторна робота №2 - Варіант C
 * Crypto++ під macOS - Контрольний приклад
 */

#include <cryptopp/osrng.h>
#include <cryptopp/drbg.h>
#include <cryptopp/sha.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/rsa.h>
#include <iostream>
#include <iomanip>
#include <chrono>

using std::cout;
using std::endl;
using std::string;
using std::hex;
using std::dec;
using std::setw;
using std::setfill;
using std::vector;
using std::min;
using std::cerr;

using namespace CryptoPP;
using namespace std::chrono;

void printHex(const string& label, const CryptoPP::byte* data, size_t len, size_t maxShow = 32) {
    cout << label << ": ";
    for (size_t i = 0; i < min(len, maxShow); i++) {
        cout << hex << setw(2) << setfill('0') << (int)data[i];
    }
    if (len > maxShow) cout << "...";
    cout << dec << " (" << len << " bytes)" << endl;
}

void printHeader(const string& title) {
    cout << "\n=== " << title << " ===" << endl;
}

int main() {
    cout << "\n╔═══════════════════════════════════════════╗" << endl;
    cout << "║  Lab2 - Crypto++ на macOS                 ║" << endl;
    cout << "╚═══════════════════════════════════════════╝" << endl;
    
    try {
        AutoSeededRandomPool rng;
        
        // 1. AutoSeededRandomPool
        printHeader("1. AutoSeededRandomPool");
        CryptoPP::byte buffer[32];
        rng.GenerateBlock(buffer, sizeof(buffer));
        printHex("GenerateBlock(32)", buffer, sizeof(buffer));
        cout << "GenerateWord32(0, 1000000): " << rng.GenerateWord32(0, 1000000) << endl;
        cout << "CanIncorporateEntropy: " << (rng.CanIncorporateEntropy() ? "true" : "false") << endl;
        
        // 2. OS_GenerateRandomBlock
        printHeader("2. OS_GenerateRandomBlock");
        CryptoPP::byte osRandom[32];
        OS_GenerateRandomBlock(false, osRandom, sizeof(osRandom));
        printHex("non-blocking", osRandom, sizeof(osRandom));
        
        // 3. Hash_DRBG
        printHeader("3. Hash_DRBG<SHA256>");
        Hash_DRBG<SHA256, 128, 440> hashDrbg;
        CryptoPP::byte seed[128];
        rng.GenerateBlock(seed, sizeof(seed));
        hashDrbg.IncorporateEntropy(seed, sizeof(seed));
        CryptoPP::byte out1[32];
        hashDrbg.GenerateBlock(out1, sizeof(out1));
        printHex("Output", out1, sizeof(out1));
        
        // Перевірка детермінованості
        Hash_DRBG<SHA256, 128, 440> hashDrbg2;
        hashDrbg2.IncorporateEntropy(seed, sizeof(seed));
        CryptoPP::byte verify[32];
        hashDrbg2.GenerateBlock(verify, sizeof(verify));
        cout << "Deterministic: " << (memcmp(out1, verify, 32) == 0 ? "YES" : "NO") << endl;
        
        // 4. HMAC_DRBG
        printHeader("4. HMAC_DRBG<SHA256>");
        HMAC_DRBG<SHA256, 128, 440> hmacDrbg;
        hmacDrbg.IncorporateEntropy(seed, sizeof(seed));
        CryptoPP::byte hmacOut[32];
        hmacDrbg.GenerateBlock(hmacOut, sizeof(hmacOut));
        printHex("Output", hmacOut, sizeof(hmacOut));
        
        // 5. Перевірка простоти
        printHeader("5. Primality Testing");
        cout << "IsPrime(997) = " << (IsPrime(Integer(997)) ? "true" : "false") << endl;
        cout << "IsPrime(1000) = " << (IsPrime(Integer(1000)) ? "true" : "false") << endl;
        cout << "RabinMillerTest(1000000007, 20) = " 
             << (RabinMillerTest(rng, Integer("1000000007"), 20) ? "prime" : "composite") << endl;
        
        // 6. Генерація safe prime
        printHeader("6. PrimeAndGenerator");
        auto t1 = high_resolution_clock::now();
        PrimeAndGenerator pg(1, rng, 512);
        auto t2 = high_resolution_clock::now();
        Integer p = pg.Prime(), q = pg.SubPrime(), g = pg.Generator();
        cout << "512-bit safe prime: " << duration_cast<milliseconds>(t2-t1).count() << " ms" << endl;
        cout << "p bits: " << p.BitCount() << ", q bits: " << q.BitCount() << ", g = " << g << endl;
        cout << "Verify p=2q+1: " << ((p == 2*q + 1) ? "YES" : "NO") << endl;
        
        // 7. RSA ключі
        printHeader("7. RSA Key Generation");
        t1 = high_resolution_clock::now();
        RSA::PrivateKey privKey;
        privKey.GenerateRandomWithKeySize(rng, 2048);
        t2 = high_resolution_clock::now();
        cout << "2048-bit RSA key: " << duration_cast<milliseconds>(t2-t1).count() << " ms" << endl;
        cout << "n bits: " << privKey.GetModulus().BitCount() << ", e = " << privKey.GetPublicExponent() << endl;
        cout << "Validate(3): " << (privKey.Validate(rng, 3) ? "VALID" : "INVALID") << endl;
        
        // Тест шифрування
        RSA::PublicKey pubKey(privKey);
        Integer m("12345678901234567890");
        Integer c = pubKey.ApplyFunction(m);
        Integer d = privKey.CalculateInverse(rng, c);
        cout << "Encrypt/Decrypt test: " << (m == d ? "PASS" : "FAIL") << endl;
        
        // 8. Бенчмарк
        printHeader("8. Benchmark");
        const size_t MB = 1024 * 1024;
        CryptoPP::byte* buf = new CryptoPP::byte[MB];
        
        t1 = high_resolution_clock::now();
        rng.GenerateBlock(buf, MB);
        t2 = high_resolution_clock::now();
        auto ms = duration_cast<milliseconds>(t2-t1).count();
        if (ms == 0) ms = 1;
        cout << "AutoSeededRandomPool: " << (MB * 1000.0 / ms / 1024 / 1024) << " MB/s" << endl;
        
        delete[] buf;
        
        cout << "\n=== DONE ===" << endl;
        return 0;
    } catch (const std::exception& e) {
        cerr << "[ERROR] " << e.what() << endl;
        return 1;
    }
}
