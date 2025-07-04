#!/bin/bash

# ==============================================================================
# Headless Ghidra Taint Analysis Test Script
#
# This script automates the process of running the MNN taint analysis script
# on a target binary using Ghidra's headless analyzer. It creates a temporary
# Ghidra project for each run and cleans it up afterwards.
#
# Usage:
#   ./run_headless_test.sh
#
# ==============================================================================

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
# Path to your Ghidra installation's analyzeHeadless script
GHIDRA_HEADLESS_PATH="/Applications/ghidra_11.0.3_PUBLIC/support/analyzeHeadless"

# The directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# The binary to be analyzed
TARGET_BINARY="$SCRIPT_DIR/emotion_ferplus_mnn"

# The analysis script to run (must be in the SCRIPT_DIR)
ANALYSIS_SCRIPT="mnn_analyzer.py"

# Ghidra project name (the parent directory will be temporary)
GHIDRA_PROJECT_NAME="HeadlessTaintAnalysis"

# Output files
LOG_FILE="$SCRIPT_DIR/headless_analysis.log"
JSON_OUTPUT_FILE="$SCRIPT_DIR/taint_analysis_results.json"


# --- Pre-flight Checks ---
if [ ! -f "$GHIDRA_HEADLESS_PATH" ]; then
    echo "ERROR: Ghidra headless analyzer not found at '$GHIDRA_HEADLESS_PATH'"
    echo "Please update the GHIDRA_HEADLESS_PATH variable in this script."
    exit 1
fi

if [ ! -f "$TARGET_BINARY" ]; then
    echo "ERROR: Target binary not found at '$TARGET_BINARY'"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/$ANALYSIS_SCRIPT" ]; then
    echo "ERROR: Analysis script not found at '$SCRIPT_DIR/$ANALYSIS_SCRIPT'"
    exit 1
fi

# --- Temporary Project Setup & Cleanup ---
# Create a temporary directory for the Ghidra project.
# Using a subshell for `mktemp` to be compatible with more systems.
TMP_GHIDRA_PROJECT_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ghidra-project')

# Define a cleanup function to be called on script exit.
cleanup() {
  echo "Cleaning up temporary Ghidra project: $TMP_GHIDRA_PROJECT_DIR"
  rm -rf "$TMP_GHIDRA_PROJECT_DIR"
}
# Register the cleanup function to run when the script exits (for any reason).
trap cleanup EXIT


# --- Main Execution ---
echo "Starting headless Ghidra taint analysis..."
echo "  - Temp Ghidra Project: $TMP_GHIDRA_PROJECT_DIR/$GHIDRA_PROJECT_NAME"
echo "  - Target Binary:       $TARGET_BINARY"
echo "  - Analysis Script:     $ANALYSIS_SCRIPT"
echo "  - Log File:            $LOG_FILE"
echo "  - JSON Output:         $JSON_OUTPUT_FILE"

# Clean up previous analysis log and result files
echo "Cleaning up previous analysis logs..."
rm -f "$LOG_FILE"
rm -f "$JSON_OUTPUT_FILE"

# Export the environment variable for the Python script to know where to save the JSON output.
export TAINT_ANALYSIS_JSON_OUTPUT="$JSON_OUTPUT_FILE"

# Run the headless analyzer
echo "Running analyzeHeadless... This may take a few minutes."
"$GHIDRA_HEADLESS_PATH" "$TMP_GHIDRA_PROJECT_DIR" "$GHIDRA_PROJECT_NAME" \
    -import "$TARGET_BINARY" \
    -scriptPath "$SCRIPT_DIR" \
    -postScript "$ANALYSIS_SCRIPT" \
    -log "$LOG_FILE" \
    -overwrite # Allows Ghidra to overwrite the project if it somehow exists

echo "Ghidra analysis finished."


# --- Verification ---
if [ -f "$JSON_OUTPUT_FILE" ]; then
    echo ""
    echo "✅ SUCCESS: Taint analysis results saved to '$JSON_OUTPUT_FILE'"
    echo "You can view the full Ghidra log at '$LOG_FILE'"
else
    echo ""
    echo "❌ FAILURE: The output file '$JSON_OUTPUT_FILE' was not created."
    echo "Please check the log file for errors: '$LOG_FILE'"
    exit 1
fi

# --- 清理 Python .py.class 缓存文件 ---
echo "Cleaning up Python .py.class cache files in $SCRIPT_DIR ..."
find "$SCRIPT_DIR" -name "*py.class" -type f -delete

exit 0 