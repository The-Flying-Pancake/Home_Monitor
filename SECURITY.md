# Security policy

Home Monitor stores credentials for the machines it manages (SSH keys, passwords and API tokens),
so security reports are very welcome and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Instead, use GitHub's private
reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Only the
maintainer sees the report.

Helpful things to include:
- the version (Settings, System, or the `VERSION` line in `home_monitor.sh`)
- what an attacker needs first (network access, a login, a particular role)
- the steps to reproduce it and what happens

This is a hobby project maintained in spare time, so replies may take a few days. Fixes go out as
a new release, and the release notes say what was fixed once it is safe to do so.

## Supported versions

Only the latest release gets security fixes. Settings, Updates (or `bash home_monitor.sh --upgrade`)
brings an install up to date.

## Verifying a release

Each release's `home_monitor.sh` is signed. The public key is in `deploy/release-signers`:

```bash
ssh-keygen -Y verify -f deploy/release-signers -I release@home-monitor -n home-monitor-release -s home_monitor.sh.sig < home_monitor.sh
```
The fingerprint of the release key is `SHA256:VfgS3MkxWYcs7WXOVRScDX29tjA3pWXCf5d4VwDByQQ`.
The in-app updater makes the same check before it installs anything.
