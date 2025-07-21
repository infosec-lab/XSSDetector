#!/usr/bin/env bash
# ------------------------------------------------------------
#  XSSDetector – Build Script (Unix)
#  Author : Vikas Kumar
#  Version: 2025.1.0 (AI Edition)
# ------------------------------------------------------------

set -euo pipefail

# === Configuration ==========================================
SRC_DIR="src"
PKG_DIR="burp"
BUILD_DIR="build"
CLASS_DIR="$BUILD_DIR/classes"
DIST_DIR="dist"
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
javac -d "$CLASS_DIR" -cp "$SRC_DIR" "$SRC_DIR/$PKG_DIR/"*.java
echo "    ✓ Compilation succeeded"

echo "[2/3] Packaging ..."
jar cvf "$DIST_DIR/$JAR_NAME" -C "$CLASS_DIR" .
echo "    ✓ JAR created"

echo "[3/3] Verifying ..."
jar tf "$DIST_DIR/$JAR_NAME" >/dev/null
SIZE=$(wc -c < "$DIST_DIR/$JAR_NAME")

echo
echo "-------- Build Complete --------"
echo "Artifact : $(pwd)/$DIST_DIR/$JAR_NAME"
echo "Size     : $SIZE bytes"
echo "---------------------------------"
echo "Load into Burp Suite:"
echo "  Extender ▶ Extensions ▶ Add ▶ Java ▶ browse to JAR"
echo "---------------------------------"
