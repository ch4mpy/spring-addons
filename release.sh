#!/bin/bash
# Release spring-addons to Maven Central.
#
# Usage:
#   ./release.sh            # releases the version in pom.xml, without its -SNAPSHOT suffix
#   ./release.sh 9.4.0      # releases an explicit version
#
# What it does, in order:
#   1. checks that release-notes.md documents the version being released (the GitHub
#      Release published by .github/workflows/release.yml is built from that section,
#      so a missing section would produce an empty Release)
#   2. updates the version in the documentation snippets and commits it, if needed
#   3. runs `mvn clean install release:prepare release:perform` with the JDK of .sdkmanrc
#
# The tag pushed by release:prepare triggers .github/workflows/release.yml, which publishes
# the GitHub Release. Nothing else to do once this script returns.
set -eu

cd "$(dirname "$0")"

# SDKMAN defines `sdk` as a shell function, which a non-interactive shell does not inherit.
# sdkman-init.sh references $ZSH_VERSION/$BASH_VERSION without guards, which trips our `set -u`,
# so relax it only for the sourcing.
if ! command -v sdk > /dev/null 2>&1 && [ -s "${SDKMAN_DIR:-$HOME/.sdkman}/bin/sdkman-init.sh" ]; then
  set +u
  # shellcheck disable=SC1091
  source "${SDKMAN_DIR:-$HOME/.sdkman}/bin/sdkman-init.sh"
  set -u
fi
# sdk() reads $2 unconditionally, which trips our `set -u` even for single-argument calls.
set +u
sdk env
set -u

export JDK_JAVA_OPTIONS='--add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.text=ALL-UNNAMED --add-opens java.desktop/java.awt.font=ALL-UNNAMED'

# 1. Version to release
VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(mvn -q help:evaluate -Dexpression=project.version -DforceStdout)"
  VERSION="${VERSION%-SNAPSHOT}"
fi
TAG="spring-addons-${VERSION}"
echo "Releasing ${VERSION} (tag ${TAG})"

# 2. Refuse to release a version which has no release notes
if ! ./scripts/release-notes.sh "$VERSION" > /dev/null; then
  echo "Add a \"### \`${VERSION}\`\" section to release-notes.md first: the GitHub Release is built from it." >&2
  exit 1
fi

# 3. Keep the version in the documentation snippets in sync.
# Only the files holding a <springaddons.version> are touched and staged: any other
# pending change in the working tree is left alone.
DOCS="$(grep -rl "springaddons.version>[0-9][^<]*<" --include='*.md' --include='*.MD' . | grep -v '/target/' || true)"
BUMPED=0
if [ -n "$DOCS" ]; then
  for doc in $DOCS; do
    sed -i "s|springaddons.version>[0-9][^<]*<|springaddons.version>${VERSION}<|g" "$doc"
    if ! git diff --quiet -- "$doc"; then
      git add -- "$doc"
      BUMPED=1
      echo "Bumped the version in $doc"
    fi
  done
fi
if [ "$BUMPED" = "1" ]; then
  git commit -m "Documentation snippets for ${VERSION}"
fi

# 4. Release
mvn clean install release:prepare release:perform -DreleaseVersion="$VERSION" -Dtag="$TAG"

echo
echo "Released ${VERSION}."
echo "The GitHub Release is being published by the Release workflow:"
echo "  https://github.com/ch4mpy/spring-addons/actions/workflows/release.yml"
