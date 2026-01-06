import time
import statistics
import gc
from task1 import pq_tls_handshake
from task2 import kem_tls_demo

# Number of benchmark iterations
ITERATIONS = 50


def benchmark(func, name, iterations=ITERATIONS):
    timings = []

    # Warm-up run (not measured)
    func()

    for _ in range(iterations):
        gc.collect()  # reduce GC noise

        start = time.perf_counter()
        func()
        end = time.perf_counter()

        timings.append(end - start)

    return {
        "name": name,
        "runs": iterations,
        "mean": statistics.mean(timings),
        "median": statistics.median(timings),
        "stdev": statistics.stdev(timings) if iterations > 1 else 0.0,
        "min": min(timings),
        "max": max(timings),
        "raw": timings,
    }


def print_results(result):
    print(f"\n=== {result['name']} ===")
    print(f"Runs: {result['runs']}")
    print(f"Mean time:   {result['mean']:.6f} seconds")
    print(f"Median time: {result['median']:.6f} seconds")
    print(f"Std dev:     {result['stdev']:.6f} seconds")
    print(f"Min time:    {result['min']:.6f} seconds")
    print(f"Max time:    {result['max']:.6f} seconds")


if __name__ == "__main__":
    print("Starting PQ-TLS vs KEM-TLS efficiency comparison...\n")

    pq_results = benchmark(pq_tls_handshake, "PQ-TLS Handshake")
    kem_results = benchmark(kem_tls_demo, "KEM-TLS Handshake")

    print_results(pq_results)
    print_results(kem_results)

    speedup = pq_results["mean"] / kem_results["mean"]
    print("\n=== Relative Comparison ===")
    print(f"PQ-TLS / KEM-TLS mean time ratio: {speedup:.2f}x")

    if speedup > 1:
        print("KEM-TLS is faster on average.")
    else:
        print("PQ-TLS is faster on average.")
