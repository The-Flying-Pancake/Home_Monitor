# Contributing

Thanks for thinking about it! Ideas, bug reports and pull requests are all welcome.

## Before you start

- **Bugs:** open an issue with the version, what you did, what you expected and what happened.
  Screenshots help for anything on screen.
- **Ideas:** open an issue first for anything large, so we can agree on the shape before you
  spend time on it.
- **Security problems:** please report them privately (see [SECURITY.md](SECURITY.md)).

## How the code is put together

- Python 3.10+ with the standard library only, plus `cryptography` for the vault. Please do not
  add other dependencies.
- Vanilla JavaScript in `web/`, with no framework and no build step.
- SQL always with placeholders; subprocesses always with argument lists, never `shell=True`.
- Secrets never go into logs, command lines or replies to the browser.
- Text people read uses plain words, no serial (Oxford) comma and no em dashes. The tests check
  some of this.

## Testing

```bash
python3 tests/run_all.py          # must pass
python3 tests/browser_checks.py   # for changes to the web pages (needs Chrome or Edge)
```
Changes to the installer are covered by `tests/test_deploy.py`, which runs `home_monitor.sh` against a
fake Proxmox host.

## Pull requests

Keep them focused, add a test for what you change and describe the change in plain words. By
contributing you agree that your work is released under the MIT licence of this project.
