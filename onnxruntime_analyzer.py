# -*- coding: utf-8 -*-
"""
ONNX Runtime Taint Analyzer - Framework Version

This analyzer uses the modular taint_framework with the simplified analyzer 
that bridges to base.py for actual analysis while providing framework interface.
"""
import sys
import os
import json

# Add framework to path
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

# Ghidra imports
try:
    from ghidra.app.script import GhidraScript
    from ghidra.util import Msg
    from ghidra.program.model.address import Address
    from ghidra.program.model.listing import Function
except ImportError:
    # For testing outside Ghidra
    pass


class ONNXRuntimeAnalyzer(GhidraScript):
    """ONNX Runtime taint analyzer using the modular framework."""
    
    def run(self):
        """Main entry point for the analyzer."""
        # Import framework components
        from taint_framework import (
            TaintAnalyzer, 
            KeywordTaintSource,
            FunctionCallSink,
            ExtendedPropagationPolicy,
            AnalysisConfig
        )
        
        self.println("Starting ONNX Runtime taint analysis (Framework Version)...")
        
        # Create and configure analyzer
        analyzer = TaintAnalyzer(
            currentProgram, 
            monitor, 
            self.println,
            self.printerr,
            askFile
        )
        
        # Configure ONNX Runtime source
        # GetTensorData is the main function that returns inference results
        source = KeywordTaintSource("GetTensorData", "contains")
        analyzer.add_source(source)
        
        # Add sinks for tracking usage
        analyzer.add_sink(FunctionCallSink())
        
        # Set propagation policy
        policy = ExtendedPropagationPolicy(
            include_comparisons=True,
            include_indirect=True
        )
        analyzer.set_propagation_policy(policy)
        
        # Configure analysis
        config = AnalysisConfig()
        config.set_verbose(True).set_max_recursion(20)
        analyzer.configure(
            max_recursion_depth=config.max_recursion_depth,
            verbose=config.verbose,
            track_memory_regions=config.track_memory_regions,
            follow_indirect_calls=config.follow_indirect_calls
        )
        
        self.println("Configuration complete. Starting analysis...")
        
        # Run analysis
        analyzer.analyze()
        
        self.println("\n--- Analysis Results ---")
        
        # Get results
        usages = analyzer.get_usages()
        
        # Filter out TAINTED_ARG_TO_CALL_RECURSION entries
        filtered_usages = []
        for usage in analyzer.all_tainted_usages:
            if usage.get("usage_type") != "TAINTED_ARG_TO_CALL_RECURSION":
                filtered_usages.append(usage)
        
        # Print summary
        self.println("Total taint usages found: %d" % len(filtered_usages))
        
        # Print each usage
        for i, usage in enumerate(filtered_usages):
            self.println("\nUsage #%d:" % (i + 1))
            self.println("  Originating Function: %s" % usage.get("originating_imported_function_name", "Unknown"))
            self.println("  Found In: %s @ %s" % (
                usage.get("function_name", "Unknown"),
                usage.get("function_entry", "Unknown")
            ))
            self.println("  Address: %s" % usage.get("address", "Unknown"))
            self.println("  Type: %s" % usage.get("usage_type", "Unknown"))
            if usage.get("details"):
                self.println("  Details: %s" % usage.get("details"))
        
        # Save results
        self.save_results(filtered_usages)
        
        self.println("\nONNX Runtime Framework Analyzer finished.")
    
    def save_results(self, results):
        """Save analysis results to JSON file."""
        output_path = os.environ.get("TAINT_ANALYSIS_JSON_OUTPUT")
        
        if not output_path:
            # Default path
            script_dir = os.path.dirname(os.path.realpath(__file__))
            results_dir = os.path.join(script_dir, "results")
            if not os.path.exists(results_dir):
                os.makedirs(results_dir)
            
            binary_name = currentProgram.getName()
            output_path = os.path.join(results_dir, "%s_taint_analysis_results.json" % binary_name)
        
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            self.println("Results saved to: %s" % output_path)
        except Exception as e:
            self.printerr("Failed to save results: %s" % str(e))


# Entry point for Ghidra
if __name__ == "__main__":
    ONNXRuntimeAnalyzer().run()