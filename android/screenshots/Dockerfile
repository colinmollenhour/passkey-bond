# Android emulator image for the Play Store screenshot pipeline (capture.sh).
#
# Self-contained: it carries the same SDK pieces as the APK build image
# (eclipse-temurin:21-jdk + cmdline-tools + build-tools 36.0.0 +
# platforms;android-36, as .github/workflows/android.yml installs), so it can
# build the APK as well as run it, plus the emulator, an Android 16 (API 36)
# Google APIs x86_64 system image and Node for the CDP driver.
#
# The google_apis image (not google_apis_playstore) is a userdebug build: that
# gives `adb root` and keeps WebView remote debugging on for every app, which
# the driver needs, since the release APK only enables it in debuggable builds.
FROM eclipse-temurin:21-jdk

ENV ANDROID_HOME=/opt/android-sdk
ARG SYSTEM_IMAGE="system-images;android-36;google_apis;x86_64"
ENV SYSTEM_IMAGE=${SYSTEM_IMAGE}

# Emulator runtime libraries (headless still links X11/GL/NSS) and Node
# (>= 22, for the built-in WebSocket the driver uses).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      curl unzip zip ca-certificates nodejs \
      libpulse0 libgl1 libegl1 libnss3 libxcomposite1 libxcursor1 libxi6 libxtst6 \
      libxdamage1 libxrandr2 libxkbcommon0 libxkbfile1 libdbus-1-3 libx11-xcb1 \
      libfontconfig1 libbsd0 libasound2t64 \
 && rm -rf /var/lib/apt/lists/* \
 && node -e 'if (+process.versions.node.split(".")[0] < 22) { console.error("need Node >= 22, got " + process.version); process.exit(1) }'

RUN mkdir -p "$ANDROID_HOME/cmdline-tools" \
 && curl -fsSL -o /tmp/clt.zip https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip \
 && echo "4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583  /tmp/clt.zip" | sha256sum -c - \
 && unzip -q /tmp/clt.zip -d "$ANDROID_HOME/cmdline-tools" \
 && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
 && rm /tmp/clt.zip \
 && yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null \
 && "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
      "build-tools;36.0.0" "platforms;android-36" "platform-tools" > /dev/null \
 && chmod -R a+rX "$ANDROID_HOME"

# Separate layer: the emulator and system image are the big, slow downloads.
RUN "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "emulator" "$SYSTEM_IMAGE" > /dev/null \
 && chmod -R a+rX "$ANDROID_HOME"

ENV PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
