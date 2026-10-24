#!/usr/bin/env bash
# Builds build/PassRelay.app from macos/PassRelayMenu and code-signs it.
# Ad-hoc signature by default; set PASSRELAY_SIGN_IDENTITY to sign with a Developer ID.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$ROOT/macos/PassRelayMenu"
APP="$ROOT/build/PassRelay.app"

[[ -f "$ROOT/VERSION" ]] || echo "0.1.0" > "$ROOT/VERSION"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"

echo "==> swift build -c release ($VERSION)"
swift build -c release --package-path "$PKG"
BIN_DIR="$(swift build -c release --package-path "$PKG" --show-bin-path)"

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/PassRelayMenu" "$APP/Contents/MacOS/PassRelayMenu"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>PassRelayMenu</string>
    <key>CFBundleIdentifier</key><string>io.passrelay.menubar</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>PassRelay</string>
    <key>CFBundleDisplayName</key><string>PassRelay</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
    <key>NSHumanReadableCopyright</key><string>Copyright © $(date +%Y) PassRelay contributors</string>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null

if [[ -n "${PASSRELAY_SIGN_IDENTITY:-}" ]]; then
    echo "==> signing with $PASSRELAY_SIGN_IDENTITY"
    codesign --force --sign "$PASSRELAY_SIGN_IDENTITY" --options runtime --timestamp "$APP"
else
    echo "==> ad-hoc signing"
    codesign --force --sign - --options runtime "$APP"
fi
codesign --verify --strict "$APP"
echo "==> built $APP"
