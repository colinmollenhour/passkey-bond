#!/usr/bin/env bash
# Captures the Google Play phone screenshots on a headless Android emulator.
#
#   ./android/screenshots/capture.sh            # build the APK, then capture
#   ./android/screenshots/capture.sh --no-build # reuse android/dist/*.apk
#
# Output: android/play/screenshots/*.png (1080x2400). Needs Docker and /dev/kvm.
# See android/screenshots/README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${SCREENSHOT_IMAGE:-passkey-bond-screenshots:36}"
STAGE="$ROOT/android/screenshots/out"
DEST="$ROOT/android/play/screenshots"
BUILD=1

for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

[ -e /dev/kvm ] || { echo "/dev/kvm is missing; the emulator needs KVM" >&2; exit 1; }
start=$(date +%s)

echo "[capture] building image $IMAGE (cached after the first run)"
docker build -q -t "$IMAGE" "$ROOT/android/screenshots" > /dev/null

run() {
  docker run --rm --init \
    --user "$(id -u):$(id -g)" \
    --device /dev/kvm --group-add "$(stat -c %g /dev/kvm)" \
    -e HOME=/tmp \
    -v "$ROOT:/src" -w /src \
    "$@"
}

if [ "$BUILD" = 1 ]; then
  version="$(node -p "require('$ROOT/package.json').version")"
  echo "[capture] building APK $version"
  # Signs with android/signing/passkey-bond.jks, the personal key.
  run -e VERSION_NAME="$version" -e VERSION_CODE=1 "$IMAGE" ./android/build-android.sh > /dev/null
fi

rm -rf "$STAGE"
mkdir -p "$STAGE"
echo "[capture] running emulator"
run -e OUT_DIR=/src/android/screenshots/out "$IMAGE" ./android/screenshots/run.sh

# Replace the published set only after a complete, successful run.
mkdir -p "$DEST"
find "$DEST" -maxdepth 1 -name '*.png' -delete
mv "$STAGE"/*.png "$DEST"/
rmdir "$STAGE" 2> /dev/null || echo "[capture] debug output kept in $STAGE"
echo "[capture] done in $(( $(date +%s) - start ))s:"
ls -1 "$DEST"/*.png
