"""Framework-aware guard map: a guard that SCOPES a request param clears an IDOR; a role-only / auth-only
guard does not; global (APP_GUARD) vs class-level (@UseGuards) application; and the controls wiring."""
from types import SimpleNamespace

from agent.orchestrator import controls, guardmap


def _repo(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


SCOPING_GUARD = (
    "export class ApiKeyGuard implements CanActivate {\n"
    "  async canActivate(ctx: ExecutionContext): Promise<boolean> {\n"
    "    const request = ctx.switchToHttp().getRequest();\n"
    "    const sessionId = request.params['sessionId'];\n"
    "    return this.auth.validateApiKey(request.headers.key, sessionId, apiKey.allowedSessions);\n"
    "  }\n}\n")
ROLE_ONLY_GUARD = (
    "export class RolesGuard implements CanActivate {\n"
    "  canActivate(ctx: ExecutionContext): boolean {\n"
    "    const required = this.reflector.get('roles', ctx.getHandler());\n"
    "    return required.includes(ctx.user.role);\n"   # role check, no param scoping
    "  }\n}\n")


def test_global_scoping_guard_covers_all_routes(tmp_path):
    _repo(tmp_path, {
        "src/auth/api-key.guard.ts": SCOPING_GUARD,
        "src/app.module.ts": "providers: [{ provide: APP_GUARD, useClass: ApiKeyGuard }]\n",
        "src/x/x.controller.ts": "export class XController { findOne(@Param('id') id) {} }\n",
    })
    gm = guardmap.build(str(tmp_path))
    assert "ApiKeyGuard" in gm.scoping_classes
    assert gm.global_scoping is True
    assert gm.covers_idor(str(tmp_path / "src/x/x.controller.ts")) is True


def test_role_only_guard_is_not_scoping(tmp_path):
    _repo(tmp_path, {
        "src/auth/roles.guard.ts": ROLE_ONLY_GUARD,
        "src/app.module.ts": "providers: [{ provide: APP_GUARD, useClass: RolesGuard }]\n",
    })
    gm = guardmap.build(str(tmp_path))
    assert "RolesGuard" not in gm.scoping_classes   # role check alone does not scope a resource
    assert gm.global_scoping is False               # so a role-only global guard does NOT clear IDOR


def test_class_level_useguards_covers_only_that_file(tmp_path):
    _repo(tmp_path, {
        "src/auth/api-key.guard.ts": SCOPING_GUARD,
        "src/a/a.controller.ts": "@UseGuards(ApiKeyGuard)\nexport class AController { get(@Param('id') id) {} }\n",
        "src/b/b.controller.ts": "export class BController { get(@Param('id') id) {} }\n",
    })
    gm = guardmap.build(str(tmp_path))
    assert gm.global_scoping is False
    assert gm.covers_idor(str(tmp_path / "src/a/a.controller.ts")) is True
    assert gm.covers_idor(str(tmp_path / "src/b/b.controller.ts")) is False


def test_no_framework_no_coverage(tmp_path):
    _repo(tmp_path, {"app.py": "def handler(id):\n    return db.get(id)\n"})
    gm = guardmap.build(str(tmp_path))
    assert gm.global_scoping is False
    assert gm.covers_idor(str(tmp_path / "app.py")) is False


def test_id_handlers_honor_framework_guard():
    # a handler with NO inline ownership guard, but a framework scoping guard covers its file
    class _GM:
        def covers_idor(self, file=""):
            return file == "covered.ts"

    routes = [SimpleNamespace(method="GET", path="/users/{id}", function="findOne", file="covered.ts")]
    handlers = controls._id_handlers(".", routes, gm=_GM())
    assert handlers and handlers[0]["has_guard"] is True
    assert handlers[0]["framework_guard"] is True
    # same handler, NOT covered -> not guarded (would be an IDOR candidate)
    routes2 = [SimpleNamespace(method="GET", path="/users/{id}", function="findOne", file="other.ts")]
    assert controls._id_handlers(".", routes2, gm=_GM())[0]["has_guard"] is False
