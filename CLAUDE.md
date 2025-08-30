# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **ML Engine Taint Analyzer** - a security analysis tool that performs taint analysis on machine learning inference engine binaries using Ghidra. The analyzer tracks data flow from tainted sources (e.g., tensor data, model inputs) through the binary to identify potential security vulnerabilities.

## Core Architecture

### Framework Structure
- `taint_framework/` - Modular framework for taint analysis
  - `core/analyzer.py` - Bridge between base.py analyzer and modular framework (TaintAnalyzer class)
  - `core/types.py` - Core type definitions (TaintType, UsageType, etc.)
  - `core/sources.py` - Taint source definitions
  - `core/sinks.py` - Taint sink definitions
  - `core/rules.py` - Custom analysis rules
  - `core/policies.py` - Taint propagation policies
  - `core/state.py` - Analysis state management

### Analyzer Scripts
- `onnxruntime_analyzer.py` - ONNX Runtime binary analyzer
- `mnn_analyzer.py` - MNN framework binary analyzer  
- `library_analyzer.py` - Generic library function taint analyzer

## Development Commands

### Running Analysis

```bash
# Run ONNX Runtime analyzer
./run_framework_analyzer.sh onnx sample/emotion_ferplus_onnxruntime

# Run MNN analyzer
./run_framework_analyzer.sh mnn sample/emotion_ferplus_mnn

# Run library analyzer (requires library name and optional function substring)
./run_framework_analyzer.sh library sample/binary libExample.so getTensorData

# Specify custom Ghidra path
./run_framework_analyzer.sh -g ~/path/to/ghidra/support/analyzeHeadless onnx sample/binary
```

### Output Locations
- Analysis logs: `logs/` directory
- Results (JSON): `results/` directory
- Temporary Ghidra projects are auto-cleaned

## Important Notes

1. **Ghidra Dependency**: Requires Ghidra 11.0.3+ with analyzeHeadless script
   - Default path: `~/Documents/t00ls/ghidra_11.0.3_PUBLIC/support/analyzeHeadless`
   - Override with `-g` flag

2. **Jython 2.7 Compatibility**: All analyzer scripts must be compatible with Jython 2.7 (Ghidra's Python environment)
   - No type hints
   - No f-strings
   - Use `# -*- coding: utf-8 -*-` for encoding

3. **Framework Bridge**: The `taint_framework/core/analyzer.py` bridges to a `base.py` implementation (referenced but not present in repo)

4. **Sample Binaries**: The `sample/` directory contains pre-compiled ML engine binaries for testing

## Analysis Flow

1. Script invocation via `run_framework_analyzer.sh`
2. Ghidra headless analyzer imports the binary
3. Framework analyzer script runs with configured sources/sinks
4. Taint propagation tracks data flow through P-code operations
5. Results exported to JSON in `results/` directory