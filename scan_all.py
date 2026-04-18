#!/usr/bin/env python3
"""
ClaudeGuard Multi-Skill Scanner
================================
Runs every available skill against a target directory and produces a
consolidated markdown report.

Usage:
    python3 scan_all.py /path/to/project                  # run all
    python3 scan_all.py /path/to/project --skills security,web-ui
    python3 scan_all.py /path/to/project --output report.md
    python3 scan_all.py /path/to/project --severity P1    # only P0+P1
    python3 scan_all.py /path/to/project --json           # JSON output

Each skill must have an `auto_audit.py` at:
    qa-skills/<skill-name>/auto_audit.py

The audit script is invoked as:
    python3 auto_audit.py <target_path>

And is expected to print findings in the form (one per line):
    [SEVERITY] path:line — message
e.g.:
    [P0] src/rc.js:42 — RevenueCat API key uses placeholder
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import List, Optional

SKILL_DIR = Path(__file__).parent
AVAILABLE_SKILLS = [
    d.name for d in SKILL_DIR.iterdir()
    if d.is_dir() and (d / "auto_audit.py").exists() and not d.name.startswith(".")
]

SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "INFO": 3}
FINDING_RE = re.compile(r"^\[(P[012]|INFO)\]\s+([^\s:]+(?::\d+)?)\s*—\s*(.+)$")

# Pattern used by most skills' report.md — "### P0.1 [TAG] Title"
# followed by "- **Location:** `path:line`"
REPORT_HEADER_RE = re.compile(r"^###\s+(P[012])\.\d+\s+(?:\[[^\]]+\]\s+)?(.+?)\s*$")
REPORT_LOCATION_RE = re.compile(r"-\s+\*\*Location:\*\*\s+`([^`]+)`")


@dataclass
class Finding:
    severity: str
    file: str
    line: Optional[int]
    message: str
    skill: str

    def as_row(self) -> str:
        loc = self.file + (f":{self.line}" if self.line else "")
        return f"- **[{self.severity}]** `{loc}` — {self.message}"


@dataclass
class SkillRun:
    skill: str
    ok: bool
    duration_s: float
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    raw_output: str = ""


def run_skill(skill: str, target: Path, timeout: int = 120) -> SkillRun:
    """Invoke a skill's auto_audit.py and parse findings from its stdout."""
    import time
    audit_script = SKILL_DIR / skill / "auto_audit.py"
    if not audit_script.exists():
        return SkillRun(skill=skill, ok=False, duration_s=0, error=f"no auto_audit.py at {audit_script}")

    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(audit_script), str(target)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(audit_script.parent),
        )
    except subprocess.TimeoutExpired:
        return SkillRun(skill=skill, ok=False, duration_s=time.time() - t0, error="timeout")
    except Exception as e:
        return SkillRun(skill=skill, ok=False, duration_s=time.time() - t0, error=str(e))

    duration = time.time() - t0
    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    findings: List[Finding] = []

    # Strategy 1: [PX] <path:line> — <msg> lines in stdout
    for line in output.splitlines():
        m = FINDING_RE.match(line.strip())
        if not m:
            continue
        sev, location, msg = m.group(1), m.group(2), m.group(3).strip()
        if ":" in location:
            path, _, line_s = location.rpartition(":")
            try:
                line_no = int(line_s)
            except ValueError:
                path, line_no = location, None
        else:
            path, line_no = location, None
        findings.append(Finding(severity=sev, file=path, line=line_no, message=msg, skill=skill))

    # Strategy 2: some skills write to report.md in their own dir
    # Format: "### P0.1 [TAG] Title" followed by "- **Location:** `path:line`"
    if not findings:
        report_md = audit_script.parent / "report.md"
        if report_md.exists() and report_md.stat().st_mtime > (time.time() - 600):
            # Parse markdown headers + next location line
            content = report_md.read_text(errors="ignore")
            lines = content.splitlines()
            for i, raw in enumerate(lines):
                h = REPORT_HEADER_RE.match(raw)
                if not h:
                    continue
                sev, title = h.group(1), h.group(2).strip()
                location = "?"
                line_no: Optional[int] = None
                # Look ahead up to 6 lines for the Location bullet
                for j in range(i + 1, min(i + 7, len(lines))):
                    loc_match = REPORT_LOCATION_RE.search(lines[j])
                    if loc_match:
                        location = loc_match.group(1)
                        if ":" in location:
                            path, _, line_s = location.rpartition(":")
                            try:
                                line_no = int(line_s)
                                location = path
                            except ValueError:
                                pass
                        break
                findings.append(Finding(
                    severity=sev, file=location, line=line_no, message=title, skill=skill,
                ))

    return SkillRun(
        skill=skill,
        ok=proc.returncode in (0, 1),  # treat non-zero-but-parsable as ok (some scanners exit 1 when findings exist)
        duration_s=duration,
        findings=findings,
        error=None if proc.returncode in (0, 1) else f"exit {proc.returncode}",
        raw_output=output[-4000:],  # cap for report size
    )


def filter_findings(findings: List[Finding], min_severity: str) -> List[Finding]:
    cutoff = SEVERITY_ORDER.get(min_severity, 99)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= cutoff]


def group_by_severity(findings: List[Finding]) -> dict:
    out = {"P0": [], "P1": [], "P2": [], "INFO": []}
    for f in findings:
        out.setdefault(f.severity, []).append(f)
    return out


def write_markdown(target: Path, runs: List[SkillRun], out_path: Optional[Path] = None) -> str:
    """Build a consolidated markdown report."""
    from datetime import datetime
    lines: List[str] = []
    lines.append(f"# ClaudeGuard Scan Report — {target.name}")
    lines.append(f"*Target: `{target}`*")
    lines.append(f"*Generated: {datetime.now().isoformat(timespec='seconds')}*")
    lines.append("")

    # Summary matrix
    all_findings: List[Finding] = []
    for r in runs:
        all_findings.extend(r.findings)

    total_p0 = sum(1 for f in all_findings if f.severity == "P0")
    total_p1 = sum(1 for f in all_findings if f.severity == "P1")
    total_p2 = sum(1 for f in all_findings if f.severity == "P2")

    lines.append("## Summary")
    lines.append(f"- 🔴 P0: **{total_p0}**")
    lines.append(f"- 🟡 P1: **{total_p1}**")
    lines.append(f"- 🟢 P2: **{total_p2}**")
    lines.append(f"- Skills run: {len(runs)} ({sum(1 for r in runs if r.ok)} ok, {sum(1 for r in runs if not r.ok)} failed)")
    lines.append("")

    # Per-skill summary table
    lines.append("## Per-Skill Results")
    lines.append("| Skill | Status | P0 | P1 | P2 | Duration |")
    lines.append("|-------|--------|----|----|----|----------|")
    for r in runs:
        status = "✅" if r.ok else f"❌ {r.error or ''}"
        p0 = sum(1 for f in r.findings if f.severity == "P0")
        p1 = sum(1 for f in r.findings if f.severity == "P1")
        p2 = sum(1 for f in r.findings if f.severity == "P2")
        lines.append(f"| {r.skill} | {status} | {p0} | {p1} | {p2} | {r.duration_s:.1f}s |")
    lines.append("")

    # Findings by severity
    grouped = group_by_severity(all_findings)
    for sev in ("P0", "P1", "P2"):
        items = grouped.get(sev, [])
        if not items:
            continue
        icon = {"P0": "🔴", "P1": "🟡", "P2": "🟢"}.get(sev, "•")
        lines.append(f"## {icon} {sev} Findings ({len(items)})")
        for f in sorted(items, key=lambda x: (x.skill, x.file, x.line or 0)):
            loc = f.file + (f":{f.line}" if f.line else "")
            lines.append(f"- `{loc}` *(from {f.skill})* — {f.message}")
        lines.append("")

    # Per-skill raw output (for failed scans)
    failed = [r for r in runs if not r.ok]
    if failed:
        lines.append("## Failed Scans (raw)")
        for r in failed:
            lines.append(f"### {r.skill}")
            lines.append(f"Error: {r.error}")
            if r.raw_output:
                lines.append("```")
                lines.append(r.raw_output[-800:])
                lines.append("```")
            lines.append("")

    content = "\n".join(lines)
    if out_path:
        out_path.write_text(content)
    return content


def main():
    parser = argparse.ArgumentParser(description="Run all ClaudeGuard skills on a target directory")
    parser.add_argument("target", help="Path to scan")
    parser.add_argument("--skills", help="Comma-separated skills (default: all)")
    parser.add_argument("--output", help="Output markdown path (default: stdout)")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    parser.add_argument("--severity", default="P2", choices=["P0", "P1", "P2"],
                        help="Minimum severity (default P2 = all)")
    parser.add_argument("--timeout", type=int, default=120, help="Per-skill timeout seconds")
    parser.add_argument("--emit-test-plan", action="store_true",
                        help="After scanning, generate a full Test Plan from the findings "
                             "(invokes test-plan-generator skill). Writes to <target>/test-plan/")
    parser.add_argument("--test-plan-language", default=None, choices=["en", "he", "both"],
                        help="Override auto-detected language for the Test Plan")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: target {target} not found", file=sys.stderr)
        sys.exit(2)

    skills = args.skills.split(",") if args.skills else AVAILABLE_SKILLS
    # Validate
    for s in skills:
        if s not in AVAILABLE_SKILLS:
            print(f"warning: unknown skill '{s}' (have: {', '.join(AVAILABLE_SKILLS)})", file=sys.stderr)

    runs: List[SkillRun] = []
    for skill in skills:
        if skill not in AVAILABLE_SKILLS:
            continue
        print(f"→ running {skill}...", file=sys.stderr)
        run = run_skill(skill, target, timeout=args.timeout)
        # Apply severity filter
        if args.severity != "P2":
            run.findings = filter_findings(run.findings, args.severity)
        runs.append(run)
        status = "ok" if run.ok else f"FAIL ({run.error})"
        print(f"  {status} — {len(run.findings)} findings in {run.duration_s:.1f}s", file=sys.stderr)

    if args.json:
        out = {
            "target": str(target),
            "runs": [
                {
                    "skill": r.skill,
                    "ok": r.ok,
                    "duration_s": r.duration_s,
                    "error": r.error,
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in runs
            ],
        }
        text = json.dumps(out, indent=2, ensure_ascii=False)
    else:
        text = write_markdown(target, runs, out_path=Path(args.output).resolve() if args.output else None)

    if args.output:
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)

    # ── Optional: generate full Test Plan from findings ──
    if args.emit_test_plan:
        print("\n→ generating Test Plan from findings...", file=sys.stderr)

        # Dump findings to a temp JSON file that test-plan-generator can consume
        import tempfile
        findings_payload = {
            "runs": [
                {
                    "skill": r.skill,
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in runs if r.ok
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump(findings_payload, tf, ensure_ascii=False)
            findings_path = tf.name

        tpg_script = SKILL_DIR / "test-plan-generator" / "auto_audit.py"
        if not tpg_script.exists():
            print(f"  ✗ test-plan-generator not found at {tpg_script}", file=sys.stderr)
        else:
            cmd = [sys.executable, str(tpg_script), str(target),
                   "--findings-json", findings_path]
            if args.test_plan_language:
                cmd += ["--language", args.test_plan_language]
            try:
                result = subprocess.run(cmd, timeout=300)
                if result.returncode == 0:
                    print(f"  ✓ Test Plan written to {target}/test-plan/", file=sys.stderr)
                else:
                    print(f"  ✗ test-plan-generator exited {result.returncode}", file=sys.stderr)
            except subprocess.TimeoutExpired:
                print("  ✗ test-plan-generator timed out", file=sys.stderr)


if __name__ == "__main__":
    main()
