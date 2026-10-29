#!/bin/bash
# Print the release-notes.md section of a given version, without its heading.
#
# Usage: ./scripts/release-notes.sh 9.4.0
#
# Exits with 1 and prints nothing on stdout when there is no section for that version.
# Used by .github/workflows/release.yml to build the body of GitHub Releases, and
# by release.sh to refuse releasing a version whose notes are missing.
set -eu

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>, e.g. $0 9.4.0" >&2
  exit 2
fi

NOTES_FILE="$(dirname "$0")/../release-notes.md"

# The section starts at "### `<version>`" and ends at the next "### " or "## " heading.
# "#### " sub-headings (used inside 9.4.0, for instance) are part of the section.
SECTION="$(awk -v heading="### \`${VERSION}\`" '
  $0 == heading { found = 1; next }
  found && (/^### / || /^## /) { exit }
  found { print }
' "$NOTES_FILE")"

# Trim leading and trailing blank lines
SECTION="$(printf '%s\n' "$SECTION" | sed -e '/./,$!d' -e ':a' -e '/^\n*$/{$d;N;};/\n$/ba')"

if [ -z "$SECTION" ]; then
  printf 'No "### `%s`" section found in %s\n' "$VERSION" "$NOTES_FILE" >&2
  exit 1
fi

printf '%s\n' "$SECTION"
