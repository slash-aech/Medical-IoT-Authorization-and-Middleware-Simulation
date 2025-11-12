# Realistic Auth Simulation (`final.cpp`)

This project simulates a distributed authentication protocol using AES encryption, mimicking real-world LAN or IoT environments with configurable delays, failures, and concurrency. It is designed to help you benchmark and analyze the performance and reliability of a token-based authentication system under various simulated network and hardware conditions.

---

## Features

- **AES-CBC encryption** for all protocol steps (TA→Node, Node→Middleware, TA→Middleware).
- **Token granting and validation** between Trusted Authority (TA), Node, and Middleware.
- **Configurable network, database, and node delays** to simulate real-world conditions.
- **Random request drops** to mimic unreliable networks.
- **Multi-threaded simulation** with adjustable worker count (to mimic weak or strong CPUs).
- **Tampering simulation** to test protocol robustness.
- **Human-readable summary output** (`final.txt`) and optional CSV output.

---

## Build Instructions

Requires [Crypto++](https://www.cryptopp.com/) and a C++17 compiler.

```sh
g++ -std=c++17 final.cpp -lcryptopp -O2 -pthread -o verbose
```

---

## Usage

Run the simulation with default parameters:

```sh
./verbose
```

Or customize with command-line options:

```sh
./verbose --nodes 200 --workers 4 --tamper-percent 1 --payload-bytes 512 --node-jitter 100 --net-ta-node 10 50 --net-node-mw 10 50 --db-delay 20 60 --fail-percent 3 --out results.csv
```

### **Command-Line Parameters**

| Parameter                | Description                                                      | Example Value(s)         |
|--------------------------|------------------------------------------------------------------|--------------------------|
| `--nodes N`              | Number of simulated nodes                                        | `--nodes 100`            |
| `--workers N`            | Number of concurrent worker threads                              | `--workers 2`            |
| `--tamper-percent P`     | Percentage of requests to tamper (simulate invalid tokens)       | `--tamper-percent 5`     |
| `--payload-bytes N`      | Payload size per node (in bytes)                                 | `--payload-bytes 256`    |
| `--node-jitter MS`       | Max jitter (ms) in node start times                             | `--node-jitter 50`       |
| `--net-ta-node MIN MAX`  | Min and max network delay (ms) TA → Node                        | `--net-ta-node 5 20`     |
| `--net-node-mw MIN MAX`  | Min and max network delay (ms) Node → Middleware                | `--net-node-mw 5 20`     |
| `--db-delay MIN MAX`     | Min and max DB write/processing delay (ms)                      | `--db-delay 10 30`       |
| `--fail-percent P`       | Percentage of requests to randomly drop/fail                    | `--fail-percent 2`       |
| `--out filename`         | Output CSV file name                                             | `--out myresults.csv`    |
| `--help` or `-h`         | Print usage/help message                                         | `--help`                 |

---

## Output

- **final.txt**: Human-readable summary of each run (appends new results).
- **CSV file** (default: `realistic_perf.csv`): Optional, compact per-run statistics (uncomment in code to enable).

Example summary in `final.txt`:
```
Performance Summary Report
Generated: 2025-11-12 13:58:16
-----------------------------------------
Nodes: 100
Workers: 2
Average Time Per Node: 68.406 ms
Minimum Time Observed: 32.026 ms
Maximum Time Observed: 104.118 ms
Median Time Per Node: 68.867 ms
Success Percentage: 100.00 %
Dropped Percentage: 0.00 %
Run Wall Time: 3.455371 s
-----------------------------------------
```

---

## Notes

- **Simulated delays and drops** make results more realistic for LAN/IoT scenarios, but do not reflect actual hardware/network performance.
- **Adjust parameters** to match your expected real-world environment (e.g., weak CPUs, slow networks, unreliable links).
- **Crypto++** must be installed and linkable on your system.

---

## License