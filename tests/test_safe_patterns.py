"""Known-safe pre-filter: each recognizer clears the textbook-safe shape and, critically, does NOT clear
the matching unsafe shape (a false clear = a missed bug). clears() is the detector's pre-model gate."""
import pytest

from agent.orchestrator.safe_patterns import clears

SAFE = [
    ("cmd", "const p = spawn(options.ffmpegPath, args, { stdio, detached: true });"),
    ("cmd", 'subprocess.run(["ls", path])'),
    ("cmd", "const out = execFile('/usr/bin/convert', [src, dst]);"),
    ("sqli", ".where('\"id\" = :id', { id }).setParameters({ id })"),
    ("sqli", 'db.execute("SELECT * FROM u WHERE id = %s", [uid])'),
    ("nosqli", "this.repo.findOne({ where: { id, sessionId } })"),
    ("nosqli", "prisma.user.findUnique({ where: { id } })"),
    ("ssrf", "const r = await withSafeFetch(url, resolveSafeFetchTarget(url));"),
    ("ssrf", "if (isPrivate(host)) throw new Error('blocked'); fetch(url)"),
    ("path", "const real = realpath(p); if (!real.startsWith(baseDir)) throw new Error();"),
    ("path", "const name = basename(userInput); fs.readFileSync(join(dir, name))"),
]

UNSAFE = [
    ("cmd", "exec(`convert ${userInput}`)"),
    ("cmd", "child_process.exec(cmd)"),
    ("cmd", "subprocess.run(cmd, shell=True)"),
    ("cmd", "os.system('ping ' + host)"),
    ("sqli", 'cursor.execute(f"SELECT * FROM u WHERE id={uid}")'),
    ("sqli", 'db.query("SELECT * FROM u WHERE name = \'" + name + "\'")'),
    ("nosqli", "coll.find({ $where: payload })"),
    ("nosqli", "User.findOne({ username: req.body.username })"),
    ("ssrf", "const r = await fetch(req.body.url)"),
    ("path", "fs.readFile(path.join(dir, req.query.name))"),
]


@pytest.mark.parametrize("cls,window", SAFE)
def test_safe_shapes_are_cleared(cls, window):
    assert clears(cls, window), f"{cls}: expected a known-safe clear for: {window}"


@pytest.mark.parametrize("cls,window", UNSAFE)
def test_unsafe_shapes_are_not_cleared(cls, window):
    assert clears(cls, window) is None, f"{cls}: must NOT clear an unsafe shape: {window}"


def test_unknown_class_and_bad_input_fall_through():
    assert clears("xss", "innerHTML = userInput") is None     # no recognizer -> model decides
    assert clears("", "") is None
    assert clears("cmd", None) is None
