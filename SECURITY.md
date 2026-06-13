# Security Policy

## Status

Synapse is early-stage software. It has not had a third-party security
review, a penetration test, or any independent audit. The detection engine,
the rules, and the performance numbers are real and measured, but "fast and
functional" is not the same thing as "safe to stand in front of traffic you
can't afford to have bypassed."

Synapse has the potential to protect production one day. Today it is at the
very beginning of that path. Read the rest of this file with that in mind.

## Do not rely on this in production you can't afford to have bypassed

If a bypass, a missed detection, or a crash in Synapse would cause damage you
cannot absorb, do not put Synapse in the request path for that traffic yet.
Run it in front of test targets, in staging, or next to an existing control
you already trust. The most useful thing you can do for the project right now
is run it, try to break it, and report what broke.

## Reporting a vulnerability

Report privately. Do not open a public issue for a security problem, because a
public issue discloses the weakness before there is a fix.

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the advisory form.

Direct link: https://github.com/atlas-crew/synapse/security/advisories/new

Include enough detail for someone to reproduce the issue:

- What you were running: commit or release, OS, and how Synapse was deployed.
- The configuration and rule set in effect, if they matter.
- The issue and its impact: bypass, missed detection, crash, information leak,
  denial of service, or something else.
- Step-by-step reproduction: a request, a payload, a scenario, or a script.
- What you expected to happen, and what actually happened.
- Any logs, stack traces, or captures that help.

There is no response-time commitment. Synapse is maintained by one person and
responses are best-effort. You will get an acknowledgement once the report has
been read, not on a fixed schedule.

## Supported versions

There are no security-supported releases yet. Everything published so far is
pre-release and carries no security support or backport commitment. Assume any
version can contain unpatched issues. This section will be updated when that
changes.

## Responsible disclosure

Give the maintainer a reasonable chance to fix the issue before you discuss it
in public. If you intend to publish or present your findings, coordinate the
timing through the advisory thread. Good-faith research and disclosure are
welcome, and reporters who want credit will get it.
