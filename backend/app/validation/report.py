from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"


@dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str
    data: dict = field(default_factory=dict)


@dataclass
class Report:
    name: str
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    checks: list[Check] = field(default_factory=list)

    def add(self, id: str, title: str, status: str, detail: str, **data) -> Check:
        c = Check(id, title, status, detail, data)
        self.checks.append(c)
        return c

    @property
    def overall(self) -> str:
        states = {c.status for c in self.checks}
        return FAIL if FAIL in states else WARN if WARN in states else PASS

    def counts(self) -> dict:
        out = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
        for c in self.checks:
            out[c.status] += 1
        return out

    def markdown(self) -> str:
        lines = [f"# {self.name}", "", f"Run at {self.started_at} (UTC). Overall: **{self.overall}**. "
                 + ", ".join(f"{k}: {v}" for k, v in self.counts().items()), "", "| Check | Result | Detail |", "| --- | --- | --- |"]
        lines += [f"| {c.id} {c.title} | {c.status} | {c.detail.replace('|', '/')} |" for c in self.checks]
        for c in self.checks:
            if c.data:
                lines += ["", f"## {c.id} {c.title}", "", "```json", json.dumps(c.data, indent=2, default=str)[:20000], "```"]
        return "\n".join(lines) + "\n"

    def write(self, out_dir: Path, stem: str) -> tuple[Path, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        md, js = out_dir / f"{stem}.md", out_dir / f"{stem}.json"
        md.write_text(self.markdown(), encoding="utf-8")
        js.write_text(json.dumps({"name": self.name, "started_at": self.started_at, "overall": self.overall,
                                  "checks": [asdict(c) for c in self.checks]}, indent=2, default=str), encoding="utf-8")
        return md, js

    def print(self) -> None:
        for c in self.checks:
            print(f"[{c.status:4}] {c.id:6} {c.title}: {c.detail}")
        print(f"OVERALL {self.overall}  {self.counts()}")
