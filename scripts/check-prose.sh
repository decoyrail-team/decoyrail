#!/usr/bin/env bash
# House style: prose never uses em or en dashes. This covers every tracked
# markdown file so the rule can't regress. Code comments are not checked.
set -euo pipefail
cd "$(dirname "$0")/.."

if hits=$(git grep -nI -e '—' -e '–' -- '*.md'); then
  echo "$hits"
  echo "error: em/en dash in markdown prose; use a comma, colon, semicolon, or parentheses instead" >&2
  exit 1
fi
echo "prose check: no em/en dashes in tracked markdown"
