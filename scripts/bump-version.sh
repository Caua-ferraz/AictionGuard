#!/usr/bin/env bash
# bump-version.sh — Update the version string across all files in the repo.
#
# Usage:
#   cd to the root of the repo
#   ./scripts/bump-version.sh <new-version>  (e.g. 0.3.0)
# Example:
#   ./scripts/bump-version.sh 0.3.0
#
# Files updated:
#   cmd/agentguard/main.go
#   plugins/python/pyproject.toml
#   plugins/python/agentguard/adapters/mcp.py
#   plugins/typescript/package.json
#   Makefile
#   docs/SETUP.md

set -eo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: ./scripts/bump-version.sh <new-version>  (e.g. 0.3.0)" >&2
  exit 1
fi

NEW="$1"

# Validate semver format
if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must be semver (e.g. 0.3.0), got: $NEW" >&2
  exit 1
fi

# Detect the current version from the canonical source
OLD=$(grep -m1 'version = "' cmd/agentguard/main.go | sed 's/.*"\(.*\)".*/\1/')

if [ -z "$OLD" ]; then
  echo "Error: could not detect current version from cmd/agentguard/main.go" >&2
  exit 1
fi

if [ "$OLD" = "$NEW" ]; then
  echo "Already at version $NEW — nothing to do."
  exit 0
fi

echo "Bumping $OLD -> $NEW"

FILES=(
  "cmd/agentguard/main.go"
  "plugins/python/pyproject.toml"
  "plugins/python/agentguard/adapters/mcp.py"
  "plugins/typescript/package.json"
  "Makefile"
  "docs/SETUP.md"
)

for FILE in "${FILES[@]}"; do
  if [ -f "$FILE" ]; then
    sed -i "s/$OLD/$NEW/g" "$FILE"
    echo "  Updated $FILE"
  else
    echo "  Warning: $FILE not found, skipping" >&2
  fi
done

# Sanity check — fail if old version still appears in any of the above files
REMAINING=$(grep -rn "$OLD" "${FILES[@]}" 2>/dev/null || true)
if [ -n "$REMAINING" ]; then
  echo ""
  echo "Error: old version $OLD still found in:" >&2
  echo "$REMAINING" >&2
  exit 1
fi

echo ""
echo "Done. All files updated to $NEW."
echo "Next steps:"
echo "  git add -p"
echo "  git commit -m \"Bump version to $NEW\""
echo "  git tag v$NEW"
