"""Writes CHANGELOG.md from the release notes in changelog.py.

  py -3 deploy/changelog_md.py                 CHANGELOG.md in the project (with the early build history)
  py -3 deploy/changelog_md.py --public OUT    the public repository's CHANGELOG.md (releases only)

Add a version below when a release gets one (changelog.py numbers releases; the app's version
lives in server.py).
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import changelog  # noqa: E402

VERSIONS = {38: "0.15.0", 36: "0.14.0", 34: "0.13.0", 33: "0.12.1", 32: "0.12.0", 31: "0.11.2", 30: "0.11.1", 29: "0.11.0", 28: "0.10.0", 27: "0.9.0", 26: "0.8.0", 25: "0.7.0", 24: "0.6.0", 23: "0.5.0", 22: "0.4.0", 21: "0.3.1", 20: "0.3.0"}

HEADER = '''# Changelog

Every change to Home Monitor, newest first. The app shows the same notes in shorter form under
Guide, What's changed.

## Version numbers

`APP_VERSION` in `server.py` is shown in the app, written into home_monitor.sh and recorded in every backup.

- **Minor** (0.7.0 to 0.8.0): new features or a database change (an upgrade migrates the database).
- **Patch** (0.7.0 to 0.7.1): fixes and small adjustments to existing features.
- **Major** (1.0.0): once the project is settled enough to call it finished.

Version numbers were not recorded per release before 0.3.0, so releases 1 to 19 are listed by release number and date only.

## Releases
'''


def render(public: bool) -> str:
    out = [HEADER]
    for r in sorted(changelog.RELEASES, key=lambda r: -r["id"]):
        v = VERSIONS.get(r["id"])
        out.append(f"### {v + ': ' if v else ''}Release {r['id']}, {r['title']} ({r['date']})\n")
        out.extend(f"- {i}" for i in r["items"])
        out.append("")
    if not public:
        with open(os.path.join(ROOT, "docs", "history", "early-history.md"), encoding="utf-8") as f:
            early = f.read().strip()
        out.append("## Before the in-app release notes (2026-10-29 to 2026-11-01)\n")
        out.append("The build that came before release 1, from docs/history/project-plan.md (each phase there has the full detail). "
                   "Release 1 is Phase 15 of that plan and release 2 is Phase 16.\n")
        out.append("### " + early.split("\n### ", 1)[1])
    return "\n".join(out).rstrip() + "\n"


def notes_for(version: str) -> str:
    """The release notes of one version, for a GitHub release."""
    rid = next((k for k, v in VERSIONS.items() if v == version), None)
    rel = next((r for r in changelog.RELEASES if r["id"] == rid), None)
    if not rel:
        raise SystemExit(f"No release notes for {version}: add it to VERSIONS in deploy/changelog_md.py")
    return f"## {rel['title']}\n\n" + "\n".join(f"- {i}" for i in rel["items"]) + "\n"


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--public":
        path, text = sys.argv[2], render(public=True)
    else:
        path, text = os.path.join(ROOT, "CHANGELOG.md"), render(public=False)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"Wrote {path} ({len(text)} characters)")


if __name__ == "__main__":
    main()
