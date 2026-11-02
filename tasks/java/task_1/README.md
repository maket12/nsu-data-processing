# Lab Assignment J1: RSA Key Generation Service

High-performance microservice for generating RSA key pairs (8192-bit) and issuing X.509 certificates with a client application written in Java.

---

## Architecture & Implementation Details

### 1. Non-blocking I/O Multiplexing (Java NIO Selector)
* The server uses **`java.nio.channels.Selector`** (Reactor pattern) to handle I/O events non-blockingly (`OP_ACCEPT`, `OP_READ`, `OP_WRITE`).
* Sockets are not tied to dedicated OS threads, allowing the server to scale and handle **100+ concurrent clients** (including slow and idle clients) with minimal resource consumption.

### 2. Fixed Worker Thread Pool (Crypto Worker Pool)
* 8192-bit RSA key generation is computationally expensive.
* Cryptographic computations are executed in an isolated fixed-size thread pool (`--threads <n>`), protecting the CPU from thrashing.
* Key generation: `java.security.KeyPairGenerator` (8192-bit).
* Certificate issuance and signing: **Bouncy Castle** (`org.bouncycastle.cert.X509v3CertificateBuilder`).

### 3. Generator Protection from Slow Clients (Outbound Queue)
* After generating keys and certificates, worker threads never perform blocking network writes.
* The worker thread places the result into a thread-safe `ConcurrentLinkedQueue<OutboundTask>` and wakes up the selector (`selector.wakeup()`).
* The reactor thread drains the outbound queue and writes chunks to the socket (`OP_WRITE`) when the client socket buffer is ready.
* Worker threads return immediately to process subsequent generation requests.

### 4. In-Memory Caching & Request Deduplication
* The server maintains an in-memory cache using `ConcurrentHashMap<String, CompletableFuture<KeyCertPair>>`.
* If a duplicate request for the same name arrives while generation is **already in progress**, both clients attach to the same `CompletableFuture`.
* Heavy 8192-bit RSA generation runs **strictly once**. When completed, both clients receive identical credentials.
* Subsequent queries for previously requested names are served instantly from cache.

### 5. Certificate Authority (CA Manager)
* CA private key and certificate are loaded at startup (`--ca-key`, `--ca-cert`).
* If files are missing, the server automatically generates a self-signed root CA key pair (4096-bit) and X.509 certificate with `BasicConstraints(isCA = true)` and writes them to disk.
* `Issuer Name` is fixed (configurable via `--issuer`).
* `Subject Name` matches the client's requested name (`CN=<client_name>`).

---

## Wire Protocol

1. **Request:**
   The client sends an ASCII subject name terminated by a null byte (`0x00`).
   Example: `alice\0`

2. **Response:**
   The server transmits a UTF-8 stream containing:
   - Private key in PKCS#8 PEM format:
     ```text
     -----BEGIN PRIVATE KEY-----
     ...
     -----END PRIVATE KEY-----
     ```
   - Signed X.509 certificate in PEM format:
     ```text
     -----BEGIN CERTIFICATE-----
     ...
     -----END CERTIFICATE-----
     ```
   After transmission completes, the server closes the connection.

---

## Build & Run

### Prerequisites
* JDK 21 or higher (tested on JDK 25).

### Build
```bash
./gradlew build
```

### Run Server (`KeygenServerMain`)
```bash
./gradlew run --args="--port 8080 --threads 8 --issuer 'CN=RootCA, O=KeygenService, C=US'"
```
**Options:**
* `--host <host>` — socket bind address (default: `0.0.0.0`).
* `--port <port>` — listening port (default: `8080`).
* `--threads <n>` — worker pool size for RSA generation (default: CPU cores).
* `--issuer <dn>` — Issuer Name for X.509 certificates.
* `--ca-key <path>` — path to CA private key (default: `ca.key`).
* `--ca-cert <path>` — path to CA certificate (default: `ca.crt`).
* `--key-size <bits>` — RSA key size (default: `8192`).

### Run Client (`KeygenClientMain`)
```bash
# Standard request
./gradlew runClient --args="--host localhost --port 8080 --name alice"

# Slow client simulation (3-second delay)
./gradlew runClient --args="--host localhost --port 8080 --name bob --delay 3"

# Abort simulation (immediate disconnect after request)
./gradlew runClient --args="--host localhost --port 8080 --name charlie --abort"
```
**Options:**
* `--host <host>` — server hostname or IP.
* `--port <port>` — server port.
* `--name <name>` — subject name for credentials.
* `--out-dir <path>` — output directory for `<name>.key` and `<name>.crt`.
* `--delay <sec>` — delay before reading response.
* `--abort` — abort immediately after sending request.

---

## Testing

Run tests:
```bash
./gradlew test --rerun
```
