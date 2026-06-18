#!/usr/bin/env bash
# ------------------------------------------------------------
#  XSSDetector – Build Script (Unix)
#  Version: 2025.1.0 (AI Edition)
# ------------------------------------------------------------

set -euo pipefail

# === Configuration ==========================================
SRC_DIR="src"
PKG_DIR="burp"
BUILD_DIR="build"
CLASS_DIR="$BUILD_DIR/classes"
DIST_DIR="dist"
VERSION="2.0.0"
JAR_NAME="XSSDetector.jar"
# ============================================================

echo
echo "-------- Building $JAR_NAME --------"

# Prepare folders
mkdir -p "$CLASS_DIR" "$DIST_DIR"

# Clean previous output
rm -f "$CLASS_DIR"/*.class
rm -f "$DIST_DIR/$JAR_NAME"

echo "[1/3] Compiling ..."
# Ensure Java 11 target for Burp Suite compatibility (class file version 55.0)
# Using --release 11 ensures proper system module location for JDK 11 compatibility
javac --release 11 -d "$CLASS_DIR" -cp "$SRC_DIR" "$SRC_DIR/$PKG_DIR/"*.java
echo "    ✓ Compilation succeeded (Java 11 target)"

echo "[2/3] Packaging ..."
# Find jar command (robust: PATH -> JAVA_HOME -> derived from javac location)
JAR_CMD=""
if command -v jar &> /dev/null; then
    JAR_CMD="jar"
elif [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/jar" ]; then
    JAR_CMD="$JAVA_HOME/bin/jar"
else
    JAVAC_PATH="$(command -v javac || true)"
    if [ -n "$JAVAC_PATH" ]; then
        JAVA_BIN_DIR="$(dirname "$(readlink -f "$JAVAC_PATH" 2>/dev/null || echo "$JAVAC_PATH")")"
        for cand in "$JAVA_BIN_DIR/jar" "$JAVA_BIN_DIR/jar.exe"; do
            [ -x "$cand" ] && JAR_CMD="$cand" && break
        done
    fi
fi
if [ -z "$JAR_CMD" ]; then
    echo "ERROR: jar command not found. Install a Java JDK (11+) and set JAVA_HOME."
    exit 1
fi
"$JAR_CMD" cvf "$DIST_DIR/$JAR_NAME" -C "$CLASS_DIR" .
echo "    ✓ JAR created"

echo "[3/3] Verifying ..."
"$JAR_CMD" tf "$DIST_DIR/$JAR_NAME" >/dev/null
SIZE=$(wc -c < "$DIST_DIR/$JAR_NAME")

echo
echo "-------- Build Complete --------"
echo "Artifact : $(pwd)/$DIST_DIR/$JAR_NAME"
echo "Size     : $SIZE bytes"
echo "---------------------------------"
echo "Load into Burp Suite:"
echo "  Extender ▶ Extensions ▶ Add ▶ Java ▶ browse to JAR"
echo "---------------------------------"
