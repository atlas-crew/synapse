#!/usr/bin/env bash
#
# check-deleted-css-classes.sh
# ============================
#
# Fails the build if any TSX/TS file references a CSS class that has been
# deleted from src/index.css. Catches regressions like the one in the
# pre-unification fleet/MetricCard.tsx, where `<div className="card p-6">`
# was hidden inside a template literal and survived the .card deletion
# sweep silently — leaving the component visually broken until the
# MetricCard unification fixed it by accident.
#
# How it works
# ------------
# We anchor every search on `className=` and look for one of three forms
# of the forbidden token appearing inside the className value:
#
#   1. Direct double-quoted attribute:  className="card", className="foo card bar"
#   2. Single-line template literal:    className={`card`}, className={`foo ${x} card`}
#   3. Brace expression with quoted standalone literal:
#                                       className={clsx('card', ...)},
#                                       className={isCard ? 'card' : 'other'}
#
# Anchoring on `className=` eliminates the broad false-positive surface
# you get when grepping for `card` in isolation: `<Box bg="card">` props
# (Box has `card` as a bg preset token), JSDoc comments mentioning the
# word "card", JS variable names like `colors.card.dark`, test code like
# `document.querySelector('.card')`, etc. None of those are real
# regressions — only references inside an active className value can
# cause the visual breakage we care about.
#
# False-positive avoidance
# ------------------------
# The patterns require the forbidden token to sit between a space and a
# quote (or between two quotes) inside a className value. That excludes
# hyphenated identifiers like `bg-surface-card`, `text-card-foreground`,
# and `card-dark` because the character preceding `card` in those is `-`,
# which is not in our boundary set. Component names like `MetricCard`
# and `StatCard` use uppercase `C` and the search is case-sensitive, so
# they never match the lowercase `card` token.
#
# Adding a new forbidden class
# ----------------------------
# Edit FORBIDDEN_CLASSES below. Put longer alternatives first
# (`card-header` before `card`) so the regex alternation matches the
# longest token before backtracking.
#
# Excluding a file from the check
# -------------------------------
# Add `--glob '!path/to/file'` to the rg invocation. Don't disable the
# check for a real call-site — migrate it to <Panel> instead.

set -euo pipefail

# Forbidden CSS classes deleted in commit 3ef5a81. Order matters: longer
# alternatives must come before their prefixes (`card-header` before
# `card`) so the regex engine matches the full token first.
FORBIDDEN_CLASSES='card-header|card-body|card-raised|card-glass|card-elevated|card'

# Bash variable for a literal backtick — bash double-quoted strings treat
# backticks as command substitution, so we inject the byte via $BT.
BT='`'

# Pattern 1: className="...card..." direct double-quoted attribute.
# Reads as: `className="` + (optional non-quote chars ending in space) +
# CLASS + (optional space then non-quote chars) + closing `"`. The space
# requirement on either side ensures `className="bg-surface-card"` does
# NOT match (the `card` is not preceded by a space, and trying to skip
# the optional group leaves `bg-surface-card` not starting with `card`).
PAT_DOUBLE="className=\"(?:[^\"]+ )?(${FORBIDDEN_CLASSES})(?: [^\"]+)?\""

# Pattern 2: className={`...card...`} template literal. Allows arbitrary
# expression text (like `clsx(`) between `{` and the opening backtick so
# `className={clsx(`card`)}` is also caught. The body of the template
# uses the same space-or-edge boundary as Pattern 1.
PAT_TEMPLATE="className=\\{[^${BT}}]*${BT}(?:[^${BT}]+ )?(${FORBIDDEN_CLASSES})(?: [^${BT}]+)?${BT}"

# Pattern 3: className={... 'card' ...} brace expression with a quoted
# exact match. Catches `clsx('card', cond && 'foo')`, ternary expressions
# like `className={isCard ? 'card' : 'other'}`, and any other expression
# form where the forbidden token appears as a standalone single- or
# double-quoted string literal. We use [^}]* to traverse the expression
# body but stop at the closing brace.
PAT_EXPR="className=\\{[^}]*['\"](${FORBIDDEN_CLASSES})['\"]"

# Resolve the UI src directory relative to this script so the check works
# from any cwd (developer running `pnpm lint:css-classes`, CI pnpm filter,
# direct invocation, etc).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../src"

if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: ripgrep (rg) is required but not installed." >&2
  echo "  - Local dev:        brew install ripgrep" >&2
  echo "  - GitHub Actions:   ubuntu-latest images include rg by default" >&2
  exit 2
fi

# Run the search. ripgrep exits with:
#   0 = matches found (we want to fail)
#   1 = no matches    (we want to pass)
#   2 = error         (regex syntax, file access, etc — fail loudly)
#
# Capture stdout into MATCHES and the exit code separately so we can
# distinguish "clean tree" from "rg failed" instead of silently treating
# both as success (which is the bug an earlier version of this script had).
set +e
MATCHES=$(rg \
  --type ts \
  --type-add 'tsx:*.tsx' --type tsx \
  -n \
  -e "$PAT_DOUBLE" \
  -e "$PAT_TEMPLATE" \
  -e "$PAT_EXPR" \
  "$SRC_DIR")
RG_EXIT=$?
set -e

case $RG_EXIT in
  0)
    # Matches found — print them and fail.
    echo ""
    echo "=================================================================="
    echo "ERROR: Reference to deleted CSS class found in TSX/TS file"
    echo "=================================================================="
    echo ""
    echo "$MATCHES"
    echo ""
    echo "------------------------------------------------------------------"
    echo "The following classes were deleted from src/index.css and replaced"
    echo "by the <Panel> component exported from @/ui:"
    echo ""
    echo "    .card           .card-header       .card-body"
    echo "    .card-raised    .card-glass        .card-elevated"
    echo ""
    echo "Migrate the call-site to <Panel> with an appropriate tone:"
    echo "    <Panel tone=\"default|info|success|warning|destructive|advanced|system\">"
    echo "      <Panel.Header>...</Panel.Header>"
    echo "      <Panel.Body>...</Panel.Body>"
    echo "    </Panel>"
    echo ""
    echo "See docs/development/design-system-panel.md for the full migration"
    echo "guide and tone vocabulary."
    echo "=================================================================="
    exit 1
    ;;
  1)
    # No matches — clean tree.
    echo "OK: No references to deleted CSS classes found in src/."
    exit 0
    ;;
  *)
    # Anything else (regex error, file access error, etc).
    echo "ERROR: ripgrep exited with code $RG_EXIT — check the regex or file access." >&2
    exit $RG_EXIT
    ;;
esac
