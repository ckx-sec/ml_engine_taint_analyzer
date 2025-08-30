#!/bin/bash

# ==============================================================================
# Headless Ghidra Taint Analysis Test Script - Framework Analyzers
#
# This script runs the taint_framework-based analyzers that use the modular
# framework instead of base.py directly.
#
# Usage:
#   ./run_framework_analyzer.sh [options] <analyzer_type> <path_to_binary> [additional_args]
#
# Analyzer types:
#   onnx    - Run ONNX Runtime analyzer (onnxruntime_analyzer_framework.py)
#   mnn     - Run MNN analyzer (mnn_analyzer_framework.py)
#   library - Run Library analyzer (library_analyzer_framework.py)
#             Requires: <library_name> [function_substring_fallback]
#
# Options:
#   -g, --ghidra-path <path>  Specify the path to Ghidra's analyzeHeadless
#   -h, --help                Display help message
#
# Examples:
#   ./run_framework_analyzer.sh onnx sample/emotion_ferplus_onnxruntime
#   ./run_framework_analyzer.sh mnn sample/emotion_ferplus_mnn
#   ./run_framework_analyzer.sh library sample/binary libExample.so getTensorData
#   ./run_framework_analyzer.sh -g ~/Documents/t00ls/ghidra_11.0.3_PUBLIC/support/analyzeHeadless mnn sample/emotion_ferplus_mnn
#
# ==============================================================================

set -e # Exit on error

# --- Configuration ---
# Default Ghidra path
GHIDRA_HEADLESS_PATH="~/Documents/t00ls/ghidra_11.0.3_PUBLIC/support/analyzeHeadless"

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# --- Functions ---
usage() {
    echo "Framework Taint Analysis Runner"
    echo ""
    echo "Usage: $0 [options] <analyzer_type> <path_to_binary> [additional_args]"
    echo ""
    echo "Analyzer types:"
    echo "  onnx    - Run ONNX Runtime analyzer"
    echo "  mnn     - Run MNN analyzer"
    echo "  library - Run Library analyzer (requires: <library_name> [function_substring])"
    echo ""
    echo "Options:"
    echo "  -g, --ghidra-path <path>  Path to Ghidra's analyzeHeadless script"
    echo "                            Default: ~/Documents/t00ls/ghidra_11.0.3_PUBLIC/support/analyzeHeadless"
    echo "  -h, --help                Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0 onnx sample/emotion_ferplus_onnxruntime"
    echo "  $0 mnn sample/emotion_ferplus_mnn"
    echo "  $0 library sample/binary libExample.so getTensorData"
    echo "  $0 -g /path/to/ghidra/support/analyzeHeadless onnx sample/binary"
    exit 1
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -g|--ghidra-path)
            GHIDRA_HEADLESS_PATH="$2"
            shift # past argument
            shift # past value
            ;;
        -h|--help)
            usage
            ;;
        *)
            # Stop parsing options
            break
            ;;
    esac
done

# Check remaining arguments
if [ "$#" -lt 2 ]; then
    echo "Error: Invalid number of arguments"
    echo ""
    usage
fi

ANALYZER_TYPE="$1"
TARGET_BINARY_PATH="$2"
shift 2  # Shift past analyzer type and binary path to get additional args
ADDITIONAL_ARGS=("$@")  # Capture any remaining arguments

# Expand tilde in Ghidra path
GHIDRA_HEADLESS_PATH="${GHIDRA_HEADLESS_PATH/#\~/$HOME}"

# Map analyzer type to script name
case "$ANALYZER_TYPE" in
    onnx|onnxruntime)
        ANALYSIS_SCRIPT="onnxruntime_analyzer_framework.py"
        ANALYZER_NAME="ONNX Runtime Framework"
        if [ ${#ADDITIONAL_ARGS[@]} -ne 0 ]; then
            echo "Warning: ONNX analyzer doesn't require additional arguments. Ignoring: ${ADDITIONAL_ARGS[*]}"
        fi
        ;;
    mnn)
        ANALYSIS_SCRIPT="mnn_analyzer_framework.py"
        ANALYZER_NAME="MNN Framework"
        if [ ${#ADDITIONAL_ARGS[@]} -ne 0 ]; then
            echo "Warning: MNN analyzer doesn't require additional arguments. Ignoring: ${ADDITIONAL_ARGS[*]}"
        fi
        ;;
    library|lib)
        ANALYSIS_SCRIPT="library_analyzer_framework.py"
        ANALYZER_NAME="Library Framework"
        if [ ${#ADDITIONAL_ARGS[@]} -eq 0 ]; then
            echo "Error: Library analyzer requires at least a library name as additional argument"
            echo "Usage: $0 library <binary> <library_name> [function_substring]"
            exit 1
        fi
        ;;
    *)
        echo "Error: Unknown analyzer type '$ANALYZER_TYPE'"
        echo "Valid types: onnx, mnn, library"
        exit 1
        ;;
esac

# Project name for Ghidra
GHIDRA_PROJECT_NAME="FrameworkTaintAnalysis"

# Binary basename for output files
BINARY_BASENAME=$(basename "$TARGET_BINARY_PATH")

# --- Output Directories ---
LOG_DIR="$SCRIPT_DIR/logs"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$LOG_DIR"
mkdir -p "$RESULTS_DIR"

# Output files
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/${BINARY_BASENAME}_${ANALYZER_TYPE}_framework_${TIMESTAMP}.log"
JSON_OUTPUT_FILE="$RESULTS_DIR/${BINARY_BASENAME}_taint_analysis_results.json"

# --- Pre-flight Checks ---
if [ ! -f "$GHIDRA_HEADLESS_PATH" ]; then
    echo "ERROR: Ghidra headless analyzer not found at '$GHIDRA_HEADLESS_PATH'"
    echo "Please use -g option to specify the correct path"
    exit 1
fi

if [ ! -f "$TARGET_BINARY_PATH" ]; then
    echo "ERROR: Target binary not found at '$TARGET_BINARY_PATH'"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/$ANALYSIS_SCRIPT" ]; then
    echo "ERROR: Analysis script not found at '$SCRIPT_DIR/$ANALYSIS_SCRIPT'"
    echo "Make sure you have created the framework analyzer scripts"
    exit 1
fi

# Check for required framework
if [ ! -d "$SCRIPT_DIR/taint_framework" ]; then
    echo "ERROR: taint_framework directory not found at '$SCRIPT_DIR/taint_framework'"
    echo "The framework analyzers require the taint_framework package"
    exit 1
fi

# --- Create Temporary Project ---
TMP_GHIDRA_PROJECT_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ghidra-framework-project')

# Cleanup function
cleanup() {
    echo "Cleaning up temporary Ghidra project..."
    rm -rf "$TMP_GHIDRA_PROJECT_DIR"
    # Clean up Python/Jython cache files
    echo "Cleaning up cache files..."
    find "$SCRIPT_DIR" -name "*.py.class" -type f -delete 2>/dev/null || true
    find "$SCRIPT_DIR" -name "*\$py.class" -type f -delete 2>/dev/null || true
    find "$SCRIPT_DIR" -name "*.pyc" -type f -delete 2>/dev/null || true
    find "$SCRIPT_DIR/taint_framework" -name "*.py.class" -type f -delete 2>/dev/null || true
    find "$SCRIPT_DIR/taint_framework" -name "*\$py.class" -type f -delete 2>/dev/null || true
    find "$SCRIPT_DIR/taint_framework" -name "*.pyc" -type f -delete 2>/dev/null || true
}
trap cleanup EXIT

# --- Main Execution ---
echo "=============================================="
echo "Framework Taint Analysis"
echo "=============================================="
echo "Analyzer:        $ANALYZER_NAME"
echo "Target Binary:   $TARGET_BINARY_PATH"
echo "Script:          $ANALYSIS_SCRIPT"
echo "Ghidra Path:     $GHIDRA_HEADLESS_PATH"
echo "Output:"
echo "  - Log:         $LOG_FILE"
echo "  - Results:     $JSON_OUTPUT_FILE"
echo "=============================================="
echo ""

# Export environment variable for output path
export TAINT_ANALYSIS_JSON_OUTPUT="$JSON_OUTPUT_FILE"

# Run the headless analyzer
echo "Starting Ghidra headless analysis..."
echo "This may take a few minutes depending on binary size..."
echo ""

# Build the command with optional additional arguments
if [ ${#ADDITIONAL_ARGS[@]} -eq 0 ]; then
    "$GHIDRA_HEADLESS_PATH" "$TMP_GHIDRA_PROJECT_DIR" "$GHIDRA_PROJECT_NAME" \
        -import "$TARGET_BINARY_PATH" \
        -scriptPath "$SCRIPT_DIR" \
        -postScript "$ANALYSIS_SCRIPT" \
        -log "$LOG_FILE" \
        -overwrite
else
    # Pass additional arguments for library analyzer
    "$GHIDRA_HEADLESS_PATH" "$TMP_GHIDRA_PROJECT_DIR" "$GHIDRA_PROJECT_NAME" \
        -import "$TARGET_BINARY_PATH" \
        -scriptPath "$SCRIPT_DIR" \
        -postScript "$ANALYSIS_SCRIPT" "${ADDITIONAL_ARGS[@]}" \
        -log "$LOG_FILE" \
        -overwrite
fi

echo ""
echo "=============================================="
echo "Analysis Complete"
echo "=============================================="

# --- Verify Results ---
if [ -f "$JSON_OUTPUT_FILE" ]; then
    echo ""
    echo "✅ SUCCESS: Results saved to '$JSON_OUTPUT_FILE'"
else
    echo ""
    echo "❌ FAILURE: No results file was generated"
    echo "Check the log file for errors: $LOG_FILE"
    exit 1
fi

echo ""
echo "Full analysis log: $LOG_FILE"
echo ""
exit 0