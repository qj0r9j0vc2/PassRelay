#!/usr/bin/env bash
# Build, sign, notarize, and checksum a PassRelay release.
#
# Requires (for a signed, notarized build):
#   PASSRELAY_SIGN_IDENTITY   "Developer ID Application: NAME (TEAMID)"
#   PASSRELAY_NOTARY_PROFILE  a notarytool keychain profile
#                             (xcrun notarytool store-credentials PROFILE ...)
# Without them the script produces an ad-hoc signed build and says so; that build is for local
# use only and Gatekeeper will warn on other Macs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
DIST="$ROOT/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

echo "==> tests"
(cd "$ROOT" && python3 -m unittest discover -s tests -t . >/dev/null)

echo "==> python sdist"
tar -C "$ROOT" --exclude='__pycache__' -czf "$DIST/passrelay-$VERSION.tar.gz" \
  passrelay pyproject.toml README.md VERSION CHANGELOG.md LICENSE docs

echo "==> menu bar app"
"$ROOT/scripts/build-app.sh"
APP="$ROOT/build/PassRelay.app"
ZIP="$DIST/PassRelay-$VERSION.zip"

if [[ -n "${PASSRELAY_SIGN_IDENTITY:-}" && -n "${PASSRELAY_NOTARY_PROFILE:-}" ]]; then
  ditto -c -k --keepParent "$APP" "$ZIP"
  echo "==> notarizing"
  xcrun notarytool submit "$ZIP" --keychain-profile "$PASSRELAY_NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP"
  rm "$ZIP"
  ditto -c -k --keepParent "$APP" "$ZIP"
  spctl --assess --type execute --verbose "$APP"
else
  echo "!! PASSRELAY_SIGN_IDENTITY / PASSRELAY_NOTARY_PROFILE not set: ad-hoc signed, NOT notarized" >&2
  ditto -c -k --keepParent "$APP" "$ZIP"
fi

echo "==> checksums"
(cd "$DIST" && shasum -a 256 ./* > SHA256SUMS)
cat "$DIST/SHA256SUMS"
echo "Publish dist/* and verify downloads with: shasum -a 256 -c SHA256SUMS"
