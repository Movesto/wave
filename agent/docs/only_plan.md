## 1. Hardware & Orchestration Base

The foundation of this architecture is built to run entirely locally, eliminating cloud compute costs and API data leaks, specifically tuned for a 16GB VRAM limit on an RTX 5070 Ti running a native Linux host environment.

* **The Orchestrator:** A central Python `asyncio` state machine. It manages the lifecycle of the LLM, the Docker containers, and the symbolic engines. It enforces strict serialization—only loading the components needed for the current phase to prevent out-of-memory (OOM) crashes.
* **The Brain (`vLLM` + DeepSeek-R1-Distill-Qwen-14B):** Running at `Q4_K_M` quantization, the model weights consume ~8.5GB of VRAM. The orchestrator reserves ~4GB for the KV cache to support prefix caching (allowing multiple parallel hypothesis generations) and leaves ~3.5GB for system overhead. Larger models (27B+) are rejected because offloading to system RAM destroys the latency required for rapid DevSecOps loops.
* **The Episodic Memory (DuckDB):** LLMs suffer from context degradation and amnesia across long sessions. DuckDB acts as a persistent, lightweight SQL ledger. When the agent learns a framework-specific mitigation (e.g., "PyJWT >= 2.0 blocks algorithm confusion"), it writes it to DuckDB. The orchestrator queries this database before every prompt, injecting past learnings so the agent never repeats a failed attack vector.
* **The Debugging Oracle (SearXNG):** A local Docker container that proxies search queries (GitHub, StackOverflow) without rate limits. It is explicitly kept asleep until the orchestrator catches a cryptic framework error (e.g., a `Pydantic` validation crash) during testing. It fetches the documentation, feeds it to the LLM, and shuts back down.

## 2. Phase 1: Static Perception & Symbolic Math (SAST)

This phase operates on the source code to find mathematically provable flaws before the application ever boots.

* **Interprocedural Taint Slicing:** Feeding entire files into the 14B model blows up the context window and causes hallucination. The orchestrator uses **Tree-sitter** (for dynamic languages like Python/JS/Go) and **Joern CPG** (for C/C++/Rust). These parsers trace the data flow across multiple files—from the API route to the database sink—and extract only the ~30 lines of code involved in that specific execution path.
* **Auth Fixture Synthesis:** DAST tools fail when they cannot log in. Because most repositories lack comprehensive Playwright End-to-End tests, the orchestrator forces the 14B model to write a standalone Python `requests` script. This script registers a dummy user, authenticates, and extracts the JWT or session cookie. This guarantees the DAST phase will have authorized access.
* **Symbolic Pre-Computation:** The 14B model reviews the taint slice, but it does *not* write raw Z3 SMT solver code, which is highly prone to syntax errors. Instead, it writes high-level Python contracts (`@pre` and `@post` decorators).
* **Constraint Solving (CrossHair / angr):** The orchestrator passes the LLM's contract to a dedicated symbolic engine. CrossHair translates the Python contract into Z3 logic internally. If the path is vulnerable, Z3 generates the exact `SAT` byte payload required to exploit it. This mathematical proof is saved to the orchestrator's ledger.

## 3. Phase 2: Emulation & Instrumentation (The Environment)

To verify the vulnerability, the orchestrator must transition from static code to a running application.

* **VRAM Serialization:** The orchestrator unloads the 14B model from the GPU to free up system resources.
* **High-Fidelity Mocking (LocalStack):** Testing against a sterile app misses integration flaws. The orchestrator parses the repository's infrastructure files (Terraform, Docker Compose) and boots LocalStack. This provisions local, ephemeral versions of required cloud services (S3, SQS, DynamoDB) so the application behaves exactly as it would in production without mutating real external states.
* **Telemetry Injection (OpenTelemetry & ASan):** To solve the "DAST Blindness" problem, the orchestrator modifies the application's build files before booting. It injects OpenTelemetry (OTel) auto-instrumentation for web frameworks, and `-fsanitize=address` (ASan) for compiled native code.
* **Container Boot:** The target application is brought online via Docker Compose, fully instrumented and connected to the LocalStack mocks.

## 4. Phase 3: Active Probing & Remediation (DAST & Fix)

The orchestrator executes the attack on the live environment and uses the resulting telemetry to write a verified patch.

* **Grey-Box Seeding:** The orchestrator authenticates using the Auth Fixture token. It does not start by fuzzing blindly; it fires the exact Z3 `SAT` payload generated in Phase 1 directly at the target route. If the application crashes or leaks data, the vulnerability is confirmed instantly.
* **Active DAST Fuzzing:** If the Z3 payload is blocked by a runtime WAF or proxy, the orchestrator initiates targeted fuzzing (testing boundary limits, format strings, and HTTP header manipulation) using the authenticated token.
* **Root Cause Localization:** When a payload triggers a crash or a `500 Internal Server Error`, OpenTelemetry captures the distributed trace. This trace bridges the gap between the external HTTP failure and the internal code, providing the exact file name, function stack, and line number where the application failed.
* **Choke-Point Patching:** The 14B model is reloaded into VRAM. It receives the isolated Taint Slice and the OTel failure trace. To fix vulnerabilities that span multiple files (e.g., changing a route definition and a database utility), the model outputs a **Unified Diff**. The orchestrator applies this diff safely across the codebase using standard patching tools.
* **Dual-Gate Verification:** The Docker environment is restarted. The orchestrator re-fires the exact payload that previously crashed the system (Gate A: the exploit must fail safely). It then runs the repository's native unit test suite (Gate B: it must maintain a 100% pass rate). Only when both gates clear is the patch logged as verified.