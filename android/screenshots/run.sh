#!/usr/bin/env bash
# Runs inside the screenshot container (see capture.sh): boots a fresh headless
# emulator, installs the APK, sets up a clean status bar, then hands over by
# MODE: capture (default) runs driver.mjs, which seeds demo data and takes the
# shots; verify-webauthn runs the provider self-test and verify-webauthn.mjs;
# hold leaves the emulator running for debugging (docker exec into it).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APK="${APK:-$ROOT/android/dist/passkey-bond-android-signed.apk}"
MODE="${MODE:-capture}"
OUT_DIR="${OUT_DIR:-/tmp/out}"
DEVICE="${AVD_DEVICE:-pixel_7}"
PKG=bond.passkey.app

export ANDROID_USER_HOME=/tmp/android-user
export ANDROID_AVD_HOME=/tmp/android-avd
export ANDROID_EMULATOR_HOME=/tmp/android-user
mkdir -p "$ANDROID_USER_HOME" "$ANDROID_AVD_HOME"

log() { echo "[run] $*"; }
start=$(date +%s)

[ -f "$APK" ] || { echo "APK not found: $APK" >&2; exit 1; }
[ -w /dev/kvm ] || { echo "/dev/kvm is not writable in the container" >&2; exit 1; }

log "creating AVD ($DEVICE, $SYSTEM_IMAGE)"
echo no | avdmanager -s create avd -f -n shots -k "$SYSTEM_IMAGE" -d "$DEVICE" > /dev/null
cat >> "$ANDROID_AVD_HOME/shots.avd/config.ini" <<'EOF'
hw.ramSize=4096
hw.keyboard=yes
EOF

log "booting emulator"
emulator -avd shots -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data \
  -gpu swiftshader_indirect -cores 4 -netdelay none -netspeed full \
  > /tmp/emulator.log 2>&1 &
EMU_PID=$!
cleanup() {
  adb emu kill > /dev/null 2>&1 || true
  sleep 2
  kill "$EMU_PID" 2> /dev/null || true
}
trap cleanup EXIT

adb start-server > /dev/null 2>&1
timeout 180 adb wait-for-device || { tail -50 /tmp/emulator.log; exit 1; }
deadline=$(( $(date +%s) + 300 ))
until [ "$(adb shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" = 1 ]; do
  if [ "$(date +%s)" -gt "$deadline" ] || ! kill -0 "$EMU_PID" 2> /dev/null; then
    echo "emulator did not boot" >&2
    tail -50 /tmp/emulator.log >&2
    exit 1
  fi
  sleep 2
done
log "booted in $(( $(date +%s) - start ))s"

# Root adbd (the image is userdebug) so SystemUI can be restarted below. adbd
# restarts and drops the connection, which `adb root` may report as an error.
for _ in 1 2 3 4 5; do
  [ "$(adb shell id -u 2> /dev/null | tr -d '\r')" = 0 ] && break
  adb root > /dev/null 2>&1 || true
  sleep 2
  adb wait-for-device
done

# Settle the device: awake, unlocked, dark theme, gesture nav. (Animations stay
# on: with animator_duration_scale 0 the status bar clock and icons render clipped.)
adb shell svc power stayon true
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
adb shell cmd uimode night yes
adb shell cmd overlay enable com.android.internal.systemui.navbar.gestural > /dev/null 2>&1 || true
adb shell settings put system screen_off_timeout 1800000
log "screen $(adb shell wm size | tr -d '\r' | tail -1), $(adb shell wm density | tr -d '\r' | tail -1)"

# The emulated display cutout applies a few seconds after boot, and SystemUI
# sometimes keeps a status bar sized from before it: the clock and icons then
# come out clipped at the top. Wait for the cutout, then restart SystemUI until
# the status bar is as tall as the cutout inset.
cutout_top() {
  adb shell dumpsys display | grep -o 'cutout DisplayCutout{insets=Rect([0-9]*, [0-9]*' | head -1 | grep -o '[0-9]*$' || true
}
statusbar_height() {
  adb shell dumpsys window windows | grep -o 'fillx[0-9]*) [^}]*ty=STATUS_BAR ' | head -1 | grep -o '^fillx[0-9]*' | tr -dc 0-9 || true
}
for _ in $(seq 30); do
  inset=$(cutout_top)
  [ -n "$inset" ] && break
  sleep 2
done
for attempt in 1 2 3 4; do
  height=$(statusbar_height)
  [ -n "$inset" ] && [ "${height:-0}" -ge "$inset" ] && break
  log "status bar is ${height:-?}px, cutout inset ${inset:-?}px: restarting SystemUI ($attempt)"
  adb shell 'kill $(pidof com.android.systemui)' || true
  sleep 10
done
log "status bar ${height:-?}px, cutout inset ${inset:-?}px"

log "installing $(basename "$APK")"
adb install -r -g "$APK" > /dev/null

# Passkey.bond as the Credential Manager provider, for the Chrome passkey
# sheets. Chrome skips its first-run screens via its command-line file, which
# it reads on a userdebug build once it is the debug app.
PROVIDER="$PKG/$PKG.PasskeyCredentialProviderService"
adb shell settings put secure credential_service "$PROVIDER"
adb shell settings put secure credential_service_primary "$PROVIDER"
adb shell 'echo "chrome --disable-fre --no-default-browser-check --no-first-run" > /data/local/tmp/chrome-command-line'
adb shell am set-debug-app --persistent com.android.chrome
adb shell pm grant com.android.chrome android.permission.POST_NOTIFICATIONS 2> /dev/null || true

adb shell am start -W -n "$PKG/.MainActivity" > /dev/null

# Status bar demo mode (9:41, full battery and wifi, no notifications);
# driver.mjs sends the demo commands before every shot.
adb shell settings put global sysui_demo_allowed 1

case "$MODE" in
  capture)
    OUT_DIR="$OUT_DIR" node "$ROOT/android/screenshots/driver.mjs"
    ;;
  verify-webauthn)
    log "provider self-test"
    selftest=$(ANDROID_PLATFORM="$ANDROID_HOME/platforms/android-36/android.jar" \
      ANDROID_BUILD_TOOLS="$ANDROID_HOME/build-tools/36.0.0" \
      TMPDIR=/tmp "$ROOT/android/provider-selftest.sh" 2>&1) || true
    echo "$selftest"
    if ! printf '%s\n' "$selftest" | grep -q '"ok":true'; then
      echo "[verify] FAIL: provider self-test did not report ok" >&2
      exit 1
    fi
    OUT_DIR="$OUT_DIR" node "$ROOT/android/screenshots/verify-webauthn.mjs"
    ;;
  hold)
    log "holding the emulator; stop the container to end"
    trap - EXIT
    sleep infinity
    ;;
  *) echo "unknown MODE: $MODE" >&2; exit 2 ;;
esac

log "done in $(( $(date +%s) - start ))s"
