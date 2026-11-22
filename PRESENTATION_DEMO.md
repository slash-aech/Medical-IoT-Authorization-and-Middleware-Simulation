# Presentation Demo: Commands and Talking Points

This is a copy-ready sequence for presenting the simulation. Run each command
separately, in order, from the project directory. Each simulation command starts
a fresh process; its options do not carry over to the next command.

The examples save their reports under `/tmp` so they do not overwrite project
files. They are intended for Linux, macOS, or WSL.

## 1. Build the program

```bash
make
```

**Explain:** “This compiles the C++17 simulation and links it with OpenSSL. The
program models the Trusted Authority, IoT nodes, and middleware in one process;
it does not launch three real network services.”

## 2. Run the normal baseline

```bash
./tps --nodes 10 --workers 2 --messages-per-node 1 --out /tmp/miot-baseline.csv --summary /tmp/miot-baseline.txt
```

**Explain the arguments:**

- `--nodes 10`: simulate ten IoT devices.
- `--workers 2`: process work using two concurrent workers.
- `--messages-per-node 1`: send one authenticated message per device.
- `--out` and `--summary`: save this run's CSV and readable report separately
  from the other demonstrations.

**What it demonstrates:** the ordinary path—device proof, token issuance,
payload protection, and middleware validation. With no injected failures, the
requests should normally be accepted. The configured delays are simulated, so
the reported latency is not real-device or real-network performance.

## 3. Demonstrate ciphertext tampering

```bash
./tps --nodes 10 --workers 2 --messages-per-node 1 --tamper-percent 100 --out /tmp/miot-tamper.csv --summary /tmp/miot-tamper.txt
```

**New argument:** `--tamper-percent 100` flips a bit in every non-empty
ciphertext after encryption.

**What it demonstrates:** the middleware should reject the modified payload
when AES-GCM authentication fails. Look for `integrity_check_failed`. This is a
simulated alteration, not an attack on a real device or network.

## 4. Demonstrate an invalid device proof

```bash
./tps --nodes 10 --workers 2 --messages-per-node 1 --hardware-fail-percent 100 --out /tmp/miot-invalid-proof.csv --summary /tmp/miot-invalid-proof.txt
```

**New argument:** `--hardware-fail-percent 100` replaces every valid device
proof with random invalid bytes.

**What it demonstrates:** the Trusted Authority should reject the device before
it can send an authenticated message. Look for
`device_authentication_failed`. Despite the option's name, this does not test
physical hardware: the secure-element backend is software-emulated.

## 5. Demonstrate an expired token

```bash
./tps --nodes 10 --workers 2 --messages-per-node 1 --expired-percent 100 --out /tmp/miot-expired.csv --summary /tmp/miot-expired.txt
```

**New argument:** `--expired-percent 100` makes every issued token already
expired.

**What it demonstrates:** the middleware should reject requests with expired
tokens. Look for `expired_token`.

## 6. Demonstrate replay rejection

```bash
./tps --nodes 10 --workers 2 --messages-per-node 1 --replay-percent 100 --out /tmp/miot-replay.csv --summary /tmp/miot-replay.txt
```

**New argument:** `--replay-percent 100` redelivers each successfully accepted
request once.

**What it demonstrates:** the original request can be accepted, but the
duplicate should be rejected by the replay guard. Look for `replay_rejected` in
the detailed outcomes. The accepted total may still include the original
request; it is not a count of the rejected duplicate.

## 7. Exercise message-count key rotation (optional)

```bash
./tps --nodes 3 --workers 1 --messages-per-node 7 --rotate-after-messages 3 --out /tmp/miot-rotation.csv --summary /tmp/miot-rotation.txt
```

**New arguments:**

- `--messages-per-node 7`: send seven sequential messages from each device.
- `--rotate-after-messages 3`: advance that device's derived key version after
  each group of three messages.

**What it demonstrates:** the run exercises message-count-based key-version
changes while processing sequential messages. The current summary does not
print each key version, so describe this as exercising the behavior—not as
visible output proving each rotation.

## Suggested closing

“This proof of concept demonstrates an authentication and message-validation
flow under simulated conditions. It is not production-ready or formally
validated. In particular, its secure element is software-emulated, replay
state is in memory, and its latency includes simulated delays.”
