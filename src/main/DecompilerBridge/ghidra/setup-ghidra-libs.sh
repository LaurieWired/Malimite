#!/bin/bash

GHIDRA_DIR="/Users/laurie/Documents/ghidra_11.2_PUBLIC" # TODO: make this configured during install process
PATCH_DIR="$GHIDRA_DIR/Ghidra/patch"
JSON_VERSION="20210307" # latest version or desired version
JSON_JAR="json-$JSON_VERSION.jar"
DOWNLOAD_URL="https://repo1.maven.org/maven2/org/json/json/$JSON_VERSION/$JSON_JAR"

# Create the patch directory if it doesn’t exist
mkdir -p "$PATCH_DIR"

# Check if the JSON jar already exists in the patch folder
if [ ! -f "$PATCH_DIR/$JSON_JAR" ]; then
    echo "Downloading JSON library..."
    curl -o "$PATCH_DIR/$JSON_JAR" "$DOWNLOAD_URL"
    echo "JSON library downloaded to $PATCH_DIR"
else
    echo "JSON library already exists in $PATCH_DIR"
fi