# ============================================================
# cot/shapes/shape_react_syn.py
#
# Synthetic React Shape-1 examples. Real React is capped at ~186
# unique snippets, far below JS parity, so we have the local model
# author realistic React components (vulnerable or safe) plus a
# <think> trace and a shape1-format verdict.
#
# DIVERSITY: the local model is deterministic at a fixed seed, so an
# identical prompt yields identical code. v1 of this shape had only
# 6 sink x 2 label = 12 distinct prompts and produced 12 unique
# snippets cloned ~60x. This version gives every task a distinct
# (sink-category, scenario, label, variant) so each prompt is unique
# — run with a moderate temperature (WAVE_LOCAL_TEMPERATURE=0.6) for
# extra divergence on reused scenario/variant pairs.
#
# Safe branch never asks the model to JUDGE (it over-flags its own
# safe code); it states the code is safe by construction and asks it
# to explain the defense, status fixed to `safe`.
#
# Run:  $env:WAVE_LOCAL_TEMPERATURE="0.6"
#       python run_pilot.py shape_react_syn --target 600
# Output: data/cot/pilot/shape_react_syn.jsonl
# ============================================================
import random
import re
from typing import Optional

from .common import parse_verdict, normalize_safe_assistant

name = "shape_react_syn"

random.seed(45)

# (category, cwe, input_source, sink_description)
REACT_SEED_PATTERNS = [
    ("XSS via dangerouslySetInnerHTML", "CWE-79",
     "user-controlled text",
     "rendered through dangerouslySetInnerHTML={{ __html: value }}"),
    ("DOM XSS via javascript: URL", "CWE-79",
     "a user-controlled URL",
     "placed into an <a href={value}> or <img src={value}> without scheme validation"),
    ("Open redirect", "CWE-601",
     "a redirect-target param",
     "passed to window.location.assign(value) / navigate(value)"),
    ("Client-side eval injection", "CWE-95",
     "a user-entered expression",
     "evaluated with eval(value) or new Function(value)"),
    ("SSRF via fetch", "CWE-918",
     "a user-supplied URL",
     "fetched with fetch(value) inside a useEffect / event handler"),
    ("Prototype pollution via object merge", "CWE-1321",
     "a user-supplied object",
     "deep-merged into component state or a config object"),
]

SAFE_DEFENSE = {
    "CWE-79": "DOMPurify.sanitize() before rendering, or rendering as text via {value} / textContent",
    "CWE-601": "an allowlist of relative paths (rejecting absolute / protocol-relative URLs)",
    "CWE-95": "a parser / lookup table instead of eval, mapping the input to known safe operations",
    "CWE-918": "a host allowlist plus an https-only scheme check before fetch",
    "CWE-1321": "schema-validated assignment of known keys, rejecting __proto__ / constructor",
}

# Per-category realistic component scenarios: (component_name, domain, input_field).
SCENARIOS = {
    "XSS via dangerouslySetInnerHTML": [
        ("CommentBody", "a comment thread", "the submitted comment body"),
        ("ArticleContent", "a CMS article page", "the article body from the API"),
        ("MarkdownPreview", "a note editor", "the rendered markdown"),
        ("EmailPreview", "an email client", "the email HTML content"),
        ("RichTooltip", "a help system", "a tooltip HTML string"),
        ("BannerMessage", "a marketing banner", "an admin-configured HTML banner"),
        ("ProductDescription", "a product page", "the product description"),
        ("ChatBubble", "a chat app", "a formatted chat message"),
    ],
    "DOM XSS via javascript: URL": [
        ("ProfileLink", "a user profile", "the user's website URL"),
        ("AvatarImage", "a header bar", "the avatar image URL"),
        ("ShareButton", "a share dialog", "a share target URL"),
        ("ExternalLink", "an article footer", "an outbound link URL"),
        ("SponsorLogo", "a sponsor section", "a sponsor link URL"),
        ("DownloadLink", "a downloads page", "a file URL"),
        ("EmbedImage", "a gallery", "an image source URL"),
        ("MenuLink", "a nav menu", "a menu item href"),
    ],
    "Open redirect": [
        ("LoginRedirect", "a login flow", "the returnUrl query param"),
        ("LogoutRedirect", "a logout handler", "a next param"),
        ("OAuthCallback", "an OAuth callback", "a redirect_uri param"),
        ("PostCheckout", "a checkout flow", "a continue URL"),
        ("DeepLinkHandler", "a deep-link router", "a target path param"),
        ("WizardBackButton", "a setup wizard", "a returnTo param"),
        ("SsoLanding", "an SSO landing page", "a RelayState param"),
        ("InviteAccept", "an invite flow", "a redirect param"),
    ],
    "Client-side eval injection": [
        ("FormulaCell", "a spreadsheet tool", "a cell formula"),
        ("CalculatorInput", "a calculator widget", "a math expression"),
        ("QueryExpression", "a data explorer", "a filter expression"),
        ("TemplateRenderer", "a template tool", "a template string"),
        ("ChartFormula", "a charting tool", "a series formula"),
        ("RuleEvaluator", "a rules-engine UI", "a condition expression"),
        ("DynamicStyleEditor", "a theme editor", "a style expression"),
        ("SandboxRunner", "a code playground", "a code snippet"),
    ],
    "SSRF via fetch": [
        ("UrlPreview", "a link-preview widget", "a URL to preview"),
        ("WebhookTester", "a developer settings page", "a webhook URL"),
        ("ImageProxy", "an image proxy", "a remote image URL"),
        ("FeedImporter", "an RSS importer", "a feed URL"),
        ("ApiExplorer", "an API explorer", "a target endpoint URL"),
        ("OembedFetcher", "an embed tool", "an oEmbed URL"),
        ("ServiceHealthCheck", "a monitoring dashboard", "a service URL to ping"),
        ("AvatarImporter", "a profile importer", "an avatar source URL"),
    ],
    "Prototype pollution via object merge": [
        ("SettingsMerge", "a preferences page", "a partial settings object"),
        ("ConfigImporter", "an admin config page", "a pasted JSON config"),
        ("FilterState", "a search-filters panel", "a query-params object"),
        ("DynamicFormState", "a dynamic form", "a parsed form payload"),
        ("ThemeMerge", "a theme customizer", "a theme-overrides object"),
        ("StateHydrator", "an SSR hydration step", "a server state object"),
        ("ProfilePatch", "a profile editor", "a profile patch object"),
        ("PluginConfig", "a plugin manager", "a plugin options object"),
    ],
}


def prepare_tasks(limit: int) -> list[dict]:
    """Distinct (category, scenario, label) per task; variant index increments
    when the combo pool wraps, so every task_id and prompt is unique."""
    rng = random.Random(45)
    combos = []
    for ci, (cat, cwe, src, sink) in enumerate(REACT_SEED_PATTERNS):
        for si, (comp, domain, field) in enumerate(SCENARIOS[cat]):
            for label in ("vuln", "safe"):
                combos.append((ci, si, cat, cwe, src, sink, comp, domain, field, label))
    rng.shuffle(combos)

    tasks = []
    i = 0
    while len(tasks) < limit:
        ci, si, cat, cwe, src, sink, comp, domain, field, label = combos[i % len(combos)]
        variant = i // len(combos)
        tasks.append({
            "task_id": f"shape_react_syn:{label}:c{ci}:s{si}:v{variant}",
            "category": cat, "cwe": cwe, "input_source": src, "sink": sink,
            "component": comp, "domain": domain, "field": field,
            "variant": variant, "label": label,
        })
        i += 1
    return tasks[:limit]


SYSTEM = (
    "You generate chain-of-thought training data for a React/TypeScript "
    "vulnerability scanner. You author a realistic React component, then reason "
    "about the data flow and emit a structured verdict. Write idiomatic modern "
    "React (function components + hooks, TSX)."
)


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    cwe = task["cwe"]
    cat = task["category"]
    sink = task["sink"]
    label = task["label"]
    comp = task["component"]
    domain = task["domain"]
    field = task["field"]
    variant = task["variant"]

    if label == "vuln":
        guidance = (
            f"Write a VULNERABLE version: {field} flows into the sink "
            f"({sink}) with NO sanitization or validation — a real {cat} ({cwe})."
        )
        task2 = (
            f"TASK 2 — Write a <think> trace that tracks {field} from its source into "
            f"the sink and confirms the vulnerability (no protection is present)."
        )
        status_line, cwe_line = "status: confirmed", f"cwe: {cwe}"
        sev_line, line_line = "severity: HIGH | MEDIUM | LOW", "line: <line number in the snippet>"
        fix_line = "fix: <short fix description>"
    else:
        defense = SAFE_DEFENSE.get(cwe, "proper validation/escaping")
        guidance = (
            f"Write a SAFE version: {field} reaches the same area BUT is protected by "
            f"{defense}. This component is SAFE BY CONSTRUCTION; introduce no other bug."
        )
        task2 = (
            f"TASK 2 — Write a <think> trace that tracks {field} and shows how {defense} "
            f"neutralizes it before it can reach the sink. SAFE BY CONSTRUCTION — explain "
            f"the defense step by step. Do NOT conclude it is vulnerable or invent a bug."
        )
        status_line, cwe_line = "status: safe", "cwe: none"
        sev_line, line_line = "severity: none", "line: none"
        fix_line = "fix: none"

    variation_note = (
        f"Implementation variant #{variant}: use component and variable names specific "
        f"to this scenario; do not fall back to a generic boilerplate structure."
        if variant else ""
    )

    instruction = f"""Build {comp}, a React component for {domain}. It handles {field}.

{guidance}
{variation_note}

TASK 1 — Write {comp} as realistic TSX (10–22 lines), idiomatic modern React
(function component + hooks). Make it look like real app code for {domain}, not a toy.

{task2}

TASK 3 — Emit the result in EXACTLY this format:

<<<CODE file="{comp}.tsx">>>
[the component]
<<<END_CODE>>>

<think>
[your trace — 4–10 short, code-anchored sentences]
</think>

{status_line}
{cwe_line}
{sev_line}
{line_line}
trace: <one-line data flow summary naming a specific identifier>
{fix_line}
"""
    return SYSTEM, instruction


_CODE_RE = re.compile(r"<<<CODE(?:\s[^>]*)?>>>\s*\n(.*?)\n<<<END_CODE>>>", re.DOTALL)


def verify(task: dict, generated_text: str) -> Optional[dict]:
    parsed = parse_verdict(generated_text)
    if not parsed["status"] or not parsed["think"]:
        return None

    expected = "confirmed" if task["label"] == "vuln" else "safe"
    if parsed["status"] != expected:
        return None

    m = _CODE_RE.search(generated_text)
    if not m:
        return None
    code = m.group(1).strip()
    if len(code) < 80:
        return None

    asst = _CODE_RE.sub("", generated_text, count=1).strip()
    if expected == "safe":
        asst = normalize_safe_assistant(asst)

    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": asst},
        ],
        "_meta": {
            "shape": "shape1",
            "source": "react_synthetic",
            "language": "react",
            "label": expected if expected == "safe" else "vuln",
            "category": task["category"],
            "cwes": [parsed["cwe"]] if (parsed["cwe"] and expected != "safe") else [],
            "ground_truth_cwe": task["cwe"] if expected != "safe" else None,
        },
    }
