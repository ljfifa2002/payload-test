#!/usr/bin/env bash
# build-hooker.sh — 本地快速编译 HookerBridge.java → hooker.dex 并推送到设备
#
# 用法:
#   ./build-hooker.sh          # 编译并推送
#   ./build-hooker.sh --no-push  # 只编译，不推送

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAVA_SRC="$SCRIPT_DIR/app/src/main/java/com/pecker/payload/HookerBridge.java"
OUT_DIR="$SCRIPT_DIR/build/hooker"

# ---- 查找 android.jar ----
if [ -z "$ANDROID_HOME" ]; then
    # macOS 默认路径
    ANDROID_HOME="$HOME/Library/Android/sdk"
fi
if [ ! -d "$ANDROID_HOME" ]; then
    echo "ERROR: ANDROID_HOME not set or not found at $ANDROID_HOME"
    exit 1
fi

ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar"
if [ ! -f "$ANDROID_JAR" ]; then
    # 尝试找任意已安装的平台
    ANDROID_JAR=$(find "$ANDROID_HOME/platforms" -name "android.jar" | sort -V | tail -1)
fi
if [ ! -f "$ANDROID_JAR" ]; then
    echo "ERROR: android.jar not found under $ANDROID_HOME/platforms/"
    exit 1
fi

# ---- 查找 d8 ----
D8=$(find "$ANDROID_HOME/build-tools" -name "d8" | sort -V | tail -1)
if [ ! -f "$D8" ]; then
    echo "ERROR: d8 not found under $ANDROID_HOME/build-tools/"
    exit 1
fi

echo "[1/3] javac  $JAVA_SRC"
mkdir -p "$OUT_DIR/classes"
javac -source 11 -target 11 \
      -bootclasspath "$ANDROID_JAR" \
      -d "$OUT_DIR/classes" \
      "$JAVA_SRC"

echo "[2/3] d8  -> hooker.dex"
mkdir -p "$OUT_DIR/dex"
"$D8" --min-api 21 \
      --output "$OUT_DIR/dex" \
      --lib "$ANDROID_JAR" \
      $(find "$OUT_DIR/classes" -name "*.class")

cp "$OUT_DIR/dex/classes.dex" "$OUT_DIR/hooker.dex"
echo "      output: $OUT_DIR/hooker.dex ($(du -sh "$OUT_DIR/hooker.dex" | cut -f1))"

if [[ "$1" == "--no-push" ]]; then
    echo "[3/3] skip push"
    exit 0
fi

echo "[3/3] adb push -> /data/local/tmp/hooker.dex"
adb push "$OUT_DIR/hooker.dex" /data/local/tmp/hooker.dex
echo "done. 重启 smzdm App 即可生效。"
