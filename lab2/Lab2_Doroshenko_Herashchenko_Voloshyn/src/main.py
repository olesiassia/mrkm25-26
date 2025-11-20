import time
import math
import binascii
from collections import Counter
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def print_hex(data, length):
    hex_data = binascii.hexlify(data[:length]).decode("utf-8")
    formatted = " ".join(hex_data[i : i + 2] for i in range(0, len(hex_data), 2))
    print(f"{formatted}...")


def analyze_randomness(data, print_results=True):
    length = len(data)
    if print_results:
        print("\n--- Randomness Statistical Analysis ---")

    counts = Counter(data)
    expected = length / 256.0
    if print_results:
        print(f"Expected frequency for each byte: {expected:.2f}")

    chi_square = 0.0
    for i in range(256):
        observed = counts.get(i, 0)
        diff = observed - expected
        chi_square += (diff * diff) / expected

    if print_results:
        print(f"Chi-square statistic: {chi_square:.2f}")
        print("Critical value (p=0.05): 293.25")

        if chi_square < 293.25:
            print("Result: [OK] Sequence looks uniform.")
        else:
            print("Result: [FAIL] Deviation from uniformity.")

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    if print_results:
        print(f"Shannon Entropy: {entropy:.5f} bits/byte (Ideal: 8.0)")

    return chi_square, entropy


def benchmark_prng_volumes():
    runs = 100
    print(
        f"""\n=== PRNG Speed & Stats Benchmark (get_random_bytes) - Average of {
            runs
        } runs ==="""
    )

    sizes = [4096, 1024 * 1024, 10 * 1024 * 1024]

    print(
        f"""{"Size":<12} | {"Avg Time (s)":<13} | {"Avg Speed (MB/s)":<17} | {
            "Avg Chi-Sq":<12} | {"Avg Entropy":<12}"""
    )
    print("-" * 80)

    for size in sizes:
        total_duration = 0
        total_chi = 0
        total_entropy = 0

        for _ in range(runs):
            start = time.perf_counter()
            data = get_random_bytes(size)  # Generate data
            total_duration += time.perf_counter() - start

            chi, ent = analyze_randomness(data, print_results=False)
            total_chi += chi
            total_entropy += ent

        avg_duration = total_duration / runs
        avg_chi = total_chi / runs
        avg_entropy = total_entropy / runs

        size_mb = size / (1024 * 1024)
        speed = size_mb / avg_duration if avg_duration > 0 else 0

        size_str = (
            f"{size} B"
            if size < 1024
            else f"{size / 1024:.0f} KB"
            if size < 1024 * 1024
            else f"{size / (1024 * 1024):.0f} MB"
        )

        print(
            f"""{size_str:<12} | {avg_duration:<13.5f} | {speed:<17.2f} | {
                avg_chi:<12.2f} | {avg_entropy:<12.5f}"""
        )


def test_prng():
    benchmark_prng_volumes()

    series = 1000000
    print(f"\n--- Uniqueness Test ({series} series of 32 bytes) ---")
    seen = set()
    all_unique = True

    for _ in range(series):
        seq = get_random_bytes(32)

        if seq in seen:
            print("WARNING: Duplicate found!")
            all_unique = False
        seen.add(seq)

    if all_unique:
        print("Result: All series are unique.")


def test_rsa_generation():
    print("\n=== RSA Key Generation Analysis ===")

    key_sizes = [1024, 2048, 4096]
    num_runs = 50

    print(f"Number of runs for each key: {num_runs}")

    for bits in key_sizes:
        print(f"\n--- Testing RSA {bits} bits ---")
        times = []

        for i in range(num_runs):
            start = time.perf_counter()
            _ = RSA.generate(bits)
            end = time.perf_counter()

            duration = end - start
            times.append(duration)

            print(f"  Run {i + 1}: {duration:.4f} s")

        avg = sum(times) / len(times)
        variance = sum((t - avg) ** 2 for t in times) / len(times)
        std_dev = math.sqrt(variance)
        cv = (std_dev / avg) * 100

        print(f"Average time: {avg:.4f} s")
        print(f"Min: {min(times):.4f} s, Max: {max(times):.4f} s")
        print(f"Coefficient of variation: {cv:.2f}%")


def main():
    try:
        test_prng()
        test_rsa_generation()
    except Exception as e:
        print(f"\nError occurred: {e}")


if __name__ == "__main__":
    main()
