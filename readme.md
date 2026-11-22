# Three-Party Medical IoT Authentication and Middleware Simulation

A C++17 simulation of a medical-IoT authentication protocol with three logical entities:

1. **Trusted Authority (TA):** enrolls devices, verifies device possession proofs, issues signed access tokens, and derives versioned session keys.
2. **IoT Node:** proves possession of its enrolled device secret, obtains a short-lived token, encrypts its medical-data payload, and sends the authenticated request.
3. **Middleware (MW):** validates the token, timestamps, key version, replay state, and AES-GCM authentication tag before accepting a payload.

The implementation retains the original project's configurable network delays, database delay, node jitter, concurrent workers, random network drops, and performance summaries. It replaces the original unauthenticated AES-CBC message protection and hard-coded keys with an authenticated protocol.

> **Hardware-authentication limitation:** the included `SecureElement` is a software-emulated backend. It demonstrates the API and challenge-response flow, but it is not a physical TPM, secure element, PUF, or hardware-rooted identity. See `REPORT.md` before describing this feature in a project paper.

## Security features

- Device enrollment with a unique random 256-bit per-device secret.
- Fresh random challenge and HMAC-SHA-256 proof-of-possession check.
- Short-lived TA-issued access tokens authenticated with HMAC-SHA-256.
- AES-256-GCM authenticated encryption for the data payload.
- HKDF-style, domain-separated session-key derivation from a per-device secret and key version.
- Key-version changes on a configurable time interval **and** after a configurable number of messages per device.
- A bounded previous-time-version grace period for requests in flight during rotation.
- Strict timestamp checks with configurable maximum clock skew.
- Per-device increasing sequence numbers and a TTL-pruned nonce cache for replay rejection.
- Atomic replay-state updates under a mutex; replay state is committed only after cryptographic checks pass.
- Attack simulation switches for ciphertext tampering, replay, invalid device proof, expired tokens, and network drops.
- CSV and human-readable performance summaries.

## Requirements

- C++17 compiler (GCC 9+, Clang 10+, or a compatible compiler)
- OpenSSL development headers and `libcrypto`
- POSIX-like environment for `localtime_r` (Linux/macOS/WSL)

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install g++ libssl-dev
```

### Build

```bash
make
```

Or compile directly:

```bash
g++ -std=c++17 -O2 -pthread tps.cpp -lcrypto -o tps
```

A CMake build is also provided:

```bash
cmake -S . -B build
cmake --build build -j
```

### Run a normal simulation

```bash
./tps --nodes 100 --workers 4
```

### Exercise the security checks

```bash
./tps \
  --nodes 100 \
  --workers 4 \
  --messages-per-node 5 \
  --tamper-percent 5 \
  --replay-percent 5 \
  --hardware-fail-percent 5 \
  --expired-percent 5 \
  --fail-percent 2
```

### Exercise message-count rotation

```bash
./tps --nodes 10 --workers 2 --messages-per-node 10 --rotate-after-messages 3
```

This changes the derived session-key version after every three messages from a device. Time-based rotation is controlled separately by `--rotation-seconds`.

## Command-line options

| Option | Default | Meaning |
|---|---:|---|
| `--nodes N` | 100 | Number of simulated IoT devices |
| `--workers N` | 4 | Concurrent simulation workers |
| `--messages-per-node N` | 1 | Sequential authenticated messages per device |
| `--payload-bytes N` | 500 | Payload size for each message |
| `--node-jitter MS` | 30 | Random node-start delay from 0 to MS |
| `--net-ta-node MIN MAX` | 2 8 | Simulated TA-to-node delay in milliseconds |
| `--net-node-mw MIN MAX` | 2 8 | Simulated node-to-MW delay in milliseconds |
| `--db-delay MIN MAX` | 2 8 | Simulated database/processing delay in milliseconds |
| `--max-clock-skew SEC` | 5 | Maximum permitted timestamp difference |
| `--token-ttl SEC` | 60 | Lifetime of an access token |
| `--replay-ttl SEC` | 120 | Nonce-cache retention interval |
| `--rotation-seconds SEC` | 900 | Time-based key-rotation interval |
| `--rotate-after-messages N` | 10000 | Rotate the per-device message key after N messages |
| `--previous-key-grace SEC` | 30 | Grace period for a request using the immediately previous time-based key version |
| `--tamper-percent P` | 0 | Probability of flipping a ciphertext bit after encryption |
| `--replay-percent P` | 0 | Probability of redelivering an accepted request |
| `--hardware-fail-percent P` | 0 | Probability of replacing the device proof with an invalid proof |
| `--expired-percent P` | 0 | Probability of issuing an already-expired token |
| `--fail-percent P` | 0 | Probability of simulating a dropped request before protocol processing |
| `--out FILE` | `results.csv` | CSV output path |
| `--summary FILE` | `tps.txt` | Human-readable summary path |
| `--help`, `-h` | — | Print usage |

Percentages must be between 0 and 100. Delay ranges must be non-negative and minimum must not exceed maximum. Numeric configuration values must be positive where applicable.

## Output

- `tps.txt`: appends a readable summary for every run, including latency and outcome counts.
- `results.csv`: appends one row per run for spreadsheet analysis.

The latency includes the configured simulated waits and the protocol work performed in the simulation. It is not a measurement of a real medical device, physical secure element, production network, or database.

## Protocol notes

- Tokens are integrity-protected with HMAC-SHA-256. They are not encrypted; their fields are identifiers, timestamps, counters, key version, and a nonce, not medical payload data.
- Payloads are protected using AES-256-GCM. A fresh random 96-bit nonce is generated for each encryption; the device ID, sequence number, timestamp, and key version are authenticated as associated data.
- Session keys are derived separately for each device and key version from that device's enrolled secret. The TA token-signing key is generated randomly at process startup and is not persisted.
- Replay state is in-memory and resets when the simulation process exits. A production deployment would need durable, shared replay state and a distributed atomic update strategy.
- The program is a teaching/demo simulation, not a production medical security implementation.

See [`REPORT.md`](REPORT.md) for the detailed architecture, message flows, diagrams, algorithms, threat analysis, assumptions, and evaluation plan.
