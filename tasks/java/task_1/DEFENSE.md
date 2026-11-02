# Defense Speech Guide for Lab 1 (Task J1)

This cheat sheet provides a structured script and commands for presenting the lab during defense.

---

## 1. Introduction: What the program does (30-second summary)

> *"The goal of this assignment is to implement an asynchronous microservice that generates 8192-bit RSA key pairs and issues X.509 certificates over TCP, accompanied by a command-line client.*
>
> *The client connects over TCP, sends an ASCII name ending with a null byte `\0`, and receives back the private key (PKCS#8 PEM) and signed X.509 certificate (PEM). The client then saves them to `.key` and `.crt` files."*

---

## 2. Internal Architecture: How it works

Explain the four core components:

### A. Non-blocking Network I/O (NIO Selector)
* **Problem:** Creating an OS thread per connection leads to thread exhaustion and high context switching under 100+ concurrent or slow clients.
* **Our Solution:** A **Reactor pattern** powered by `java.nio.channels.Selector`. A single event loop thread multiplexes all socket events (`OP_ACCEPT`, `OP_READ`, `OP_WRITE`), easily handling hundreds of active connections without dedicated OS threads per socket.

### B. Fixed Worker Thread Pool (Crypto Worker Pool)
* **Problem:** 8192-bit RSA key generation is computationally heavy (1-3 seconds CPU per key).
* **Our Solution:** Computations run in a fixed-size thread pool (`--threads <n>`).
  * Key generation: `java.security.KeyPairGenerator` (8192-bit).
  * Certificate signing: **Bouncy Castle** (`X509v3CertificateBuilder`), signed with CA private key (`SHA256withRSA`).

### C. Worker Protection via Outbound Queue
* Worker threads **never block on network I/O**.
* Once keys and certificates are generated, the worker deposits the result into a non-blocking `ConcurrentLinkedQueue` and wakes up the selector (`selector.wakeup()`).
* The reactor thread writes data to sockets in chunks (`OP_WRITE`) whenever socket buffers are ready.
* **Result:** Worker threads are freed immediately and never stall waiting on slow clients.

### D. In-Memory Caching & Deduplication
* In-memory cache: `ConcurrentHashMap<String, CompletableFuture<KeyCertPair>>`.
* If a duplicate request arrives while generation is **already in progress**, `computeIfAbsent` returns the in-flight `CompletableFuture`. The heavy 8192-bit RSA computation is executed **only once**, and the result is distributed to both clients.
* Subsequent queries are served instantly from memory.

---

## 3. Demonstration Walkthrough (Commands)

### Step 0: Run Automated Tests
```powershell
.\gradlew.bat test --rerun
```
*What to say:*
> *"All 9 unit and integration tests execute live and pass, demonstrating CA generation, certificate validation, 100+ concurrent connections, deduplication, slow client, and abort simulation."*

---

### Terminal 1: Start Server
```powershell
.\gradlew.bat run --args="--port 8080 --threads 4"
```
*What to say:*
> *"The server initialized the CA and launched a fixed pool of 4 worker threads, listening on port 8080."*

---

### Terminal 2: Client Scenarios

#### Scenario 1: Basic request
```powershell
.\gradlew.bat runClient --args="--host localhost --port 8080 --name alice"
```
*What to say:*
> *"The client requested credentials for 'alice'. The server generated an 8192-bit RSA key, signed the certificate, and the client saved 'alice.key' and 'alice.crt'."*

#### Scenario 2: Instant Cache Hit
```powershell
.\gradlew.bat runClient --args="--host localhost --port 8080 --name alice"
```
*What to say:*
> *"The second request for 'alice' returns instantly from memory cache without repeating the heavy CPU computation."*

#### Scenario 3: Slow Client (`--delay`)
```powershell
.\gradlew.bat runClient --args="--host localhost --port 8080 --name slow_bob --delay 5"
```
While slow_bob is delaying, open another tab and run:
```powershell
.\gradlew.bat runClient --args="--host localhost --port 8080 --name quick_charlie"
```
*What to say:*
> *"The slow client did not block the server or the crypto workers. The fast client was served immediately in parallel."*

#### Scenario 4: Abort Mode (`--abort`)
```powershell
.\gradlew.bat runClient --args="--host localhost --port 8080 --name crash_test --abort"
```
*What to say:*
> *"The client aborted connection immediately after sending the request. The server handled the socket disconnect cleanly without crashing, and saved the result to cache for future requests."*

---

## 4. Answers to Common Professor Questions

* **Q: Why not one thread per client?**
  * *A: Creating an OS thread per connection wastes memory and causes excessive context switching. Under 100+ slow clients, thread creation would exhaust system resources. `Selector` multiplexes connections efficiently in non-blocking mode.*
* **Q: Why not Virtual Threads?**
  * *A: The specification explicitly instructed the use of `java.nio.channels.Selector` to guarantee deterministic control over socket `OP_WRITE` queues without depending on runtime scheduler heuristics.*
* **Q: How does deduplication work for simultaneous requests?**
  * *A: Via atomic `ConcurrentHashMap.computeIfAbsent` storing a `CompletableFuture`. Concurrent requests register callbacks on the same future, ensuring only one key generation occurs.*
* **Q: How is the certificate signed?**
  * *A: Using Bouncy Castle `JcaX509v3CertificateBuilder` with algorithm `SHA256withRSA`, signed by the CA private key.*
