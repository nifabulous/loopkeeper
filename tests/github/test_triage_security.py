"""Subprocess security contract for the GitHub issue-triage adapter.

These tests never contact GitHub or a model provider. Each run prepends a
stub directory to ``PATH``, records every stubbed invocation, and asserts
that the trust guard fails closed *before* any trusted read, model call, or
write. The stubs emit well-formed forge values so a failure can only come
from the adapter's own guard, never from malformed fixture data.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRIAGE = ROOT / "adapters" / "github" / "triage_issue.sh"

TRUSTED_SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
DIVERGENT_SHA = "0fedcba987654321fedcba9876543210fedcba98"
DEFAULT_BRANCH = "main"
REPO = "example-org/consumer"
ISSUE_NUMBER = "42"
MAX_RAW_BYTES = 4096

EXIT_TRUST = 4

_GIT_STUB = r"""
printf '%s\n' "git $*" >>"$LOOPKEEPER_TEST_LOG"
args=("$@")
if [[ "${args[0]:-}" == "-C" ]]; then
  args=("${args[@]:2}")
fi
case "${args[0]:-}" in
  rev-parse)
    case "${args[1]:-}" in
      --show-toplevel) printf '%s\n' "$LOOPKEEPER_TEST_REPO_ROOT" ;;
      HEAD) printf '%s\n' "$LOOPKEEPER_TEST_HEAD_SHA" ;;
      *) exit 1 ;;
    esac
    ;;
  show)
    printf '# Stub Trusted Policy\n\n## Categories\n- functional\n'
    ;;
  *) exit 1 ;;
esac
"""

_GH_STUB = r"""
printf '%s\n' "gh $*" >>"$LOOPKEEPER_TEST_LOG"
case "$*" in
  *"git/ref/heads/"*)
    printf '%s\n' "$LOOPKEEPER_TEST_FORGE_TIP"
    ;;
  "api repos/"*" --jq .default_branch")
    printf '%s\n' "$LOOPKEEPER_TEST_FORGE_DEFAULT"
    ;;
  "issue view"*)
    count_file="$LOOPKEEPER_TEST_DIR/issue-view-count"
    count=0
    [[ -f "$count_file" ]] && count="$(cat "$count_file")"
    count=$((count + 1))
    printf '%s' "$count" >"$count_file"
    if (( count > 1 )) && [[ -f "$LOOPKEEPER_TEST_DIR/issue-final.json" ]]; then
      cat "$LOOPKEEPER_TEST_DIR/issue-final.json"
    else
      cat "$LOOPKEEPER_TEST_DIR/issue.json"
    fi
    ;;
  "api repos/"*"/issues/"*"/comments"*)
    printf '[]\n'
    ;;
  "issue comment"*)
    printf 'stub comment created\n'
    ;;
  *) exit 1 ;;
esac
"""

# Delegates ``-c`` to the real interpreter because the bounded-stream helper
# depends on it, and fakes the packaged module entry points so no model call
# or redaction import is required to exercise the shell control flow.
_PYTHON_STUB = r"""
printf '%s\n' "python3 $*" >>"$LOOPKEEPER_TEST_LOG"
case "${1:-}" in
  -c)
    exec "$LOOPKEEPER_TEST_REAL_PYTHON" "$@"
    ;;
  -m)
    case "${2:-}" in
      loopkeeper.redaction|loopkeeper.truncate|loopkeeper.review_output)
        cat
        ;;
      loopkeeper.transport)
        output=""
        while (( $# )); do
          if [[ "$1" == "--output" ]]; then
            output="$2"
          fi
          shift
        done
        [[ -n "$output" ]] || exit 1
        printf 'Stub triage body.\n' >"$output"
        ;;
      *) exit 1 ;;
    esac
    ;;
  *)
    exec "$LOOPKEEPER_TEST_REAL_PYTHON" "$@"
    ;;
esac
"""


def _write_stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\nset -uo pipefail\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _issue_json(padding: int = 0) -> str:
    payload = {
        "number": int(ISSUE_NUMBER),
        "title": "Stub issue",
        "body": "x" * padding,
        "url": f"https://example.invalid/{ISSUE_NUMBER}",
        "state": "OPEN",
        "labels": [],
        "author": {"login": "octocat"},
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z",
    }
    return json.dumps(payload)


def _run(
    tmp_path: Path,
    *,
    head_sha: str = TRUSTED_SHA,
    forge_tip: str = TRUSTED_SHA,
    forge_default: str = DEFAULT_BRANCH,
    issue_padding: int = 0,
    final_issue_padding: int | None = None,
    env_overrides: dict[str, str] | None = None,
    drop_env: tuple[str, ...] = (),
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the triage adapter against stubbed ``git``/``gh``/``python3``."""
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    log = tmp_path / "invocations.log"
    log.touch()

    # Must be a concrete interpreter, never a PATH-resolving launcher such as
    # a pyenv shim: the stub directory is first on PATH, so a shim would
    # re-resolve "python3" back into the stub and recurse forever.
    real_python = sys.executable
    assert Path(real_python).is_file(), "sys.executable must be a real interpreter"

    _write_stub(stub_dir, "git", _GIT_STUB)
    _write_stub(stub_dir, "gh", _GH_STUB)
    _write_stub(stub_dir, "python3", _PYTHON_STUB)

    (tmp_path / "issue.json").write_text(_issue_json(issue_padding), encoding="utf-8")
    if final_issue_padding is not None:
        (tmp_path / "issue-final.json").write_text(
            _issue_json(final_issue_padding), encoding="utf-8"
        )

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env['PATH']}"
    env.update(
        {
            "LOOPKEEPER_TEST_LOG": str(log),
            "LOOPKEEPER_TEST_DIR": str(tmp_path),
            "LOOPKEEPER_TEST_REPO_ROOT": str(tmp_path / "consumer"),
            "LOOPKEEPER_TEST_HEAD_SHA": head_sha,
            "LOOPKEEPER_TEST_FORGE_TIP": forge_tip,
            "LOOPKEEPER_TEST_FORGE_DEFAULT": forge_default,
            "LOOPKEEPER_TEST_REAL_PYTHON": real_python,
            "LOOPKEEPER_REVIEW_ENABLED": "true",
            "LOOPKEEPER_API_KEY": "stub-key",
            "GH_TOKEN": "stub-token",
            "GH_REPO": REPO,
            "LOOPKEEPER_MODEL": "stub-model",
            "LOOPKEEPER_REASONING_EFFORT": "none",
            "LOOPKEEPER_MAX_INPUT_BYTES": "120000",
            "LOOPKEEPER_MAX_OUTPUT_TOKENS": "32000",
            "LOOPKEEPER_MAX_OUTPUT_BYTES": "50000",
            "LOOPKEEPER_CHECK_MAX_RAW_BYTES": str(MAX_RAW_BYTES),
            "LOOPKEEPER_TRUSTED_SHA": TRUSTED_SHA,
            "LOOPKEEPER_DEFAULT_BRANCH": DEFAULT_BRANCH,
            "LOOPKEEPER_OPERATOR": "0",
        }
    )
    for key in drop_env:
        env.pop(key, None)
    if env_overrides:
        env.update(env_overrides)

    result = subprocess.run(
        [str(TRIAGE), ISSUE_NUMBER],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        # No stdin: a guard that blocks on a read is a defect, not a pass.
        stdin=subprocess.DEVNULL,
        # Loose enough for a loaded machine, tight enough to catch a hang.
        timeout=120,
        # Non-zero exit is the expected result in most cases here; each test
        # asserts the specific code rather than letting the runner raise.
        check=False,
    )
    return result, log.read_text(encoding="utf-8").splitlines()


def _git_show_calls(invocations: list[str]) -> list[str]:
    return [line for line in invocations if " show " in line]


def _model_calls(invocations: list[str]) -> list[str]:
    return [line for line in invocations if "loopkeeper.transport" in line]


def _write_calls(invocations: list[str]) -> list[str]:
    return [line for line in invocations if line.startswith("gh issue comment")]


def test_triage_requires_trusted_sha_before_policy_read(tmp_path):
    """An unset trusted SHA must fail closed instead of defaulting to HEAD."""
    result, invocations = _run(tmp_path, drop_env=("LOOPKEEPER_TRUSTED_SHA",))

    assert result.returncode != 0, result.stdout
    assert _git_show_calls(invocations) == []
    assert _model_calls(invocations) == []


def test_triage_rejects_checkout_not_equal_to_trusted_sha(tmp_path):
    """A checkout that is not the declared trusted SHA must not be trusted."""
    result, invocations = _run(tmp_path, head_sha=DIVERGENT_SHA, forge_tip=DIVERGENT_SHA)

    assert result.returncode != 0, result.stdout
    assert _git_show_calls(invocations) == []
    assert _model_calls(invocations) == []


def test_triage_rejects_non_default_branch_tip(tmp_path):
    """A checkout that is not the forge default-branch tip must fail closed."""
    result, invocations = _run(tmp_path, head_sha=TRUSTED_SHA, forge_tip=DIVERGENT_SHA)

    assert result.returncode != 0, result.stdout
    assert _git_show_calls(invocations) == []
    assert _model_calls(invocations) == []


def test_triage_rejects_oversized_initial_metadata(tmp_path):
    """Issue metadata one byte over the raw bound is unavailable evidence."""
    result, invocations = _run(tmp_path, issue_padding=MAX_RAW_BYTES + 1)

    assert result.returncode == EXIT_TRUST, result.stdout
    assert _model_calls(invocations) == []
    assert _write_calls(invocations) == []


def test_triage_rejects_oversized_final_metadata_before_write(tmp_path):
    """The pre-write recheck must be bounded and must precede any write."""
    result, invocations = _run(
        tmp_path,
        final_issue_padding=MAX_RAW_BYTES + 1,
        env_overrides={"LOOPKEEPER_OPERATOR": "1"},
    )

    assert result.returncode == EXIT_TRUST, result.stdout
    assert _write_calls(invocations) == []


def test_triage_never_calls_git_show_after_failed_trust_guard(tmp_path):
    """No trusted read may occur on any guard-failure path."""
    for kwargs in (
        {"drop_env": ("LOOPKEEPER_TRUSTED_SHA",)},
        {"head_sha": DIVERGENT_SHA, "forge_tip": DIVERGENT_SHA},
        {"forge_tip": DIVERGENT_SHA},
        {"forge_default": "not-the-default"},
    ):
        run_dir = tmp_path / f"case-{abs(hash(str(kwargs)))}"
        run_dir.mkdir()
        result, invocations = _run(run_dir, **kwargs)

        assert result.returncode != 0, f"{kwargs} unexpectedly succeeded"
        assert _git_show_calls(invocations) == [], kwargs
        assert _model_calls(invocations) == [], kwargs
        assert _write_calls(invocations) == [], kwargs
