# -*- coding: utf-8 -*-
"""
Generic Library Taint Analyzer using the Taint Framework

This analyzer allows tracking taint from arbitrary library functions through the program.
It's configurable to work with any library by specifying the library name and target functions.
"""

import os
import sys
import json
# typing module not available in Jython 2.7
# Dict, Any, List, Set, Optional types are for documentation only

# Import from the taint framework
try:
    from taint_framework import (
        TaintAnalyzer,
        KeywordTaintSource,
        UsageType,
        TaintType
    )
    from taint_framework.core.sources import TaintSource, MultiKeywordTaintSource
    from taint_framework.core.sinks import TaintSink, FunctionCallSink
    from taint_framework.core.policies import ExtendedPropagationPolicy
except ImportError as e:
    import sys
    sys.stderr.write("ERROR: Could not import taint_framework\n")
    sys.stderr.write("Import error: {}\n".format(str(e)))
    raise

# Ghidra imports
try:
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Reference, ReferenceType
except ImportError:
    # For development outside Ghidra
    PcodeOp = None
    Function = None
    Reference = None
    ReferenceType = None


class LibraryFunctionSource(TaintSource):
    """
    Custom taint source for library functions.
    
    This source can match functions from a specific library using various strategies.
    """
    
    def __init__(self, library_name, function_substring=None, exact_functions=None):
        """
        Initialize library function source.
        
        Args:
            library_name: Name of the library (e.g., "libML.so")
            function_substring: Optional substring to match in function names
            exact_functions: Optional set of exact function names to match
        """
        self.library_name = library_name
        self.function_substring = function_substring
        self.exact_functions = exact_functions or set()
        self.matched_functions = set()  # Cache matched functions
    
    def is_source(self, function):
        """Check if function is a taint source from this library"""
        if not function:
            return False
        
        func_name = function.getName()
        
        # Check exact matches first
        if func_name in self.exact_functions:
            self.matched_functions.add(func_name)
            return True
        
        # Check substring match
        if self.function_substring and self.function_substring in func_name:
            # Additional check: verify it's from the target library if possible
            # This would require checking the function's origin/namespace
            self.matched_functions.add(func_name)
            return True
        
        return False
    
    def get_tainted_output(self, pcode_op):
        """Get the tainted output from the library call"""
        return pcode_op.getOutput() if pcode_op else None
    
    def get_source_name(self):
        """Return descriptive name for this source"""
        if self.exact_functions:
            return "Library[{}:{}]".format(self.library_name, ",".join(list(self.exact_functions)[:3]))
        elif self.function_substring:
            return "Library[{}:*{}*]".format(self.library_name, self.function_substring)
        else:
            return "Library[{}]".format(self.library_name)


class LibraryBranchSink(TaintSink):
    """Track when tainted library data influences branch conditions"""
    
    def is_sink(self, pcode_op):
        """Check if this is a conditional branch"""
        return pcode_op and pcode_op.getMnemonic() == "CBRANCH"
    
    def handle_tainted_sink(self, context, pcode_op, tainted_inputs):
        """Record branch condition taint"""
        context.report_usage(
            UsageType.BRANCH_CONDITION_TAINTED,
            pcode_op=pcode_op,
            details="Library data influences branch condition"
        )
        return True


class LibraryAnalyzer(TaintAnalyzer):
    """
    Generic library taint analyzer using the taint framework.
    
    This analyzer can track taint from any library's functions through the program.
    """
    
    def __init__(self, current_program, monitor, println, printerr, 
                 library_name=None, function_substring=None, exact_functions=None, askFile=None):
        """
        Initialize the library analyzer.
        
        Args:
            current_program: Ghidra program object
            monitor: Task monitor
            println: Print function
            printerr: Error print function
            library_name: Name of the library to analyze
            function_substring: Optional substring to match in function names
            exact_functions: Optional list of exact function names
            askFile: File dialog function (optional)
        """
        TaintAnalyzer.__init__(self, current_program, monitor, println, printerr, askFile)
        
        # Set library specific configuration
        self.library_name = library_name or "unknown_library"
        self.function_substring = function_substring
        self.exact_functions = set(exact_functions) if exact_functions else set()
        self.analyzer_name = "Library Analyzer ({})".format(self.library_name)
        
        # Configure analysis
        self.configure(
            max_recursion_depth=20,
            track_memory_regions=True,
            follow_indirect_calls=True,
            verbose=True
        )
        
        # Setup components
        self._setup_sources()
        self._setup_sinks()
        self._setup_policy()
    
    def _setup_sources(self):
        """Configure library taint sources"""
        # Create library-specific source
        source = LibraryFunctionSource(
            self.library_name,
            self.function_substring,
            self.exact_functions
        )
        self.add_source(source)
        
        # Store reference for reporting
        self.library_source = source
    
    def _setup_sinks(self):
        """Configure sinks for library analysis"""
        # Track branches
        self.add_sink(LibraryBranchSink())
        
        # Track common sinks
        self.add_sink(FunctionCallSink(
            function_names={"free", "delete", "memcpy", "strcpy"},
            track_args=True,
            track_return=False
        ))
    
    def _setup_policy(self):
        """Configure propagation policy for library analysis"""
        policy = ExtendedPropagationPolicy(
            propagate_through_arithmetic=True,
            propagate_through_logical=True,
            propagate_through_memory=True,
            propagate_through_calls=True,
            max_propagation_depth=20
        )
        self.set_propagation_policy(policy)
    
    def run(self):
        """Run the library taint analysis"""
        self.println("="*60)
        self.println("Starting Library Taint Analysis")
        self.println("Library: {}".format(self.library_name))
        if self.function_substring:
            self.println("Function substring: {}".format(self.function_substring))
        if self.exact_functions:
            self.println("Exact functions: {}".format(", ".join(self.exact_functions)))
        self.println("="*60)
        
        # Run the analysis
        results = self.analyze()
        
        # Post-process results
        processed_results = self._post_process_results(results)
        
        # Print summary
        self._print_summary(processed_results)
        
        return processed_results
    
    def _post_process_results(self, results):
        """
        Post-process results to match the expected output format.
        """
        transformed_usages = []
        
        for usage in results.get_usages():
            # Transform to legacy format
            transformed = {
                "found_in_function_name": usage.function_name,
                "instruction_address": usage.address,
                "pcode_operation": usage.pcode_op,
                "originating_imported_function_name": usage.origin,
                "usage_type": usage.usage_type.value,
                "details": usage.details,
                "found_in_function_entry": usage.function_entry,
                "library": self.library_name
            }
            
            # Add optional fields
            if hasattr(usage, 'tainted_component'):
                transformed["tainted_component"] = usage.tainted_component
            
            transformed_usages.append(transformed)
        
        return transformed_usages
    
    def _print_summary(self, results):
        """Print analysis summary"""
        self.println("\n" + "="*60)
        self.println("Library Taint Analysis Summary")
        self.println("="*60)
        
        # Report matched functions
        if hasattr(self, 'library_source') and self.library_source.matched_functions:
            self.println("\nMatched library functions:")
            for func_name in sorted(self.library_source.matched_functions):
                self.println("  - {}".format(func_name))
        else:
            self.println("\nNo matching library functions found!")
        
        # Count usage types
        usage_counts = {}
        for usage in results:
            usage_type = usage.get("usage_type", "UNKNOWN")
            usage_counts[usage_type] = usage_counts.get(usage_type, 0) + 1
        
        self.println("\nTotal tainted usages: {}".format(len(results)))
        for usage_type, count in sorted(usage_counts.items()):
            self.println("  - {}: {}".format(usage_type, count))
        
        # List affected functions
        affected_functions = set()
        for usage in results:
            func_name = usage.get("found_in_function_name", "UNKNOWN")
            affected_functions.add(func_name)
        
        if affected_functions:
            self.println("\nAffected functions ({} total):".format(len(affected_functions)))
            for func_name in sorted(affected_functions):
                self.println("  - {}".format(func_name))
    
    def save_results(self, results, output_path=None):
        """Save analysis results to JSON"""
        if not output_path:
            # Use environment variable or default path
            output_path = os.getenv('TAINT_ANALYSIS_JSON_OUTPUT')
            if not output_path:
                script_dir = os.path.dirname(os.path.realpath(__file__))
                results_dir = os.path.join(script_dir, "results")
                if not os.path.exists(results_dir):
                    os.makedirs(results_dir)
                program_name = self.current_program.getName()
                library_suffix = self.library_name.replace(".", "_").replace("/", "_")
                output_path = os.path.join(
                    results_dir, 
                    "{}_{}_taint_analysis_results.json".format(program_name, library_suffix)
                )
        
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            self.println("SUCCESS: Analysis results saved to: {}".format(output_path))
        except Exception as e:
            self.printerr("ERROR: Failed to save results: {}".format(e))


def run_analysis_from_ghidra_ui(library_name=None, function_substring=None, exact_functions=None):
    """
    Main entry point when run from Ghidra's UI.
    
    Args:
        library_name: Name of the library to analyze
        function_substring: Optional substring to match in function names
        exact_functions: Optional list of exact function names
    """
    # Get Ghidra context
    try:
        current_program = globals().get('currentProgram')
        monitor = globals().get('monitor')
        println = globals().get('println', lambda x: sys.stdout.write(str(x) + "\n"))
        printerr = globals().get('printerr', lambda x: sys.stderr.write("ERROR: " + str(x) + "\n"))
        askFile = globals().get('askFile')
    except Exception as e:
        sys.stderr.write("Error: This script must be run from within Ghidra environment\n")
        sys.stderr.write("Error details: {}\n".format(e))
        return
    
    if not current_program:
        printerr("No program loaded")
        return
    
    # Get parameters from script arguments if not provided
    if not library_name:
        # Try to get from script arguments (for headless mode)
        import sys
        if len(sys.argv) > 1:
            library_name = sys.argv[1]
        if len(sys.argv) > 2:
            function_substring = sys.argv[2]
        if len(sys.argv) > 3:
            exact_functions = sys.argv[3].split(",")
    
    # Default values if still not provided
    if not library_name:
        library_name = "unknown_library"
        println("WARNING: No library name provided, using 'unknown_library'")
    
    try:
        # Create and run analyzer
        println("Starting Library taint analysis using taint_framework...")
        analyzer = LibraryAnalyzer(
            current_program=current_program,
            monitor=monitor,
            println=println,
            printerr=printerr,
            library_name=library_name,
            function_substring=function_substring,
            exact_functions=exact_functions,
            askFile=askFile
        )
        
        # Run analysis
        results = analyzer.run()
        
        # Save results
        analyzer.save_results(results)
        
        println("Library Taint Analyzer (Framework version) finished.")
        
    except Exception as e:
        import traceback
        printerr("An error occurred during analysis:")
        printerr(str(e))
        printerr(traceback.format_exc())


if __name__ == "__main__":
    # Check for command line arguments
    import sys
    
    library_name = None
    function_substring = None
    exact_functions = None
    
    if len(sys.argv) > 1:
        library_name = sys.argv[1]
    if len(sys.argv) > 2:
        function_substring = sys.argv[2]
    if len(sys.argv) > 3:
        exact_functions = sys.argv[3].split(",")
    
    if 'currentProgram' in globals() and globals().get('currentProgram') is not None:
        run_analysis_from_ghidra_ui(library_name, function_substring, exact_functions)
    else:
        sys.stderr.write("This script is designed to be run from within Ghidra's Script Manager.\n")
        sys.stderr.write("Usage: library_analyzer_framework.py <library_name> [function_substring] [exact_functions]\n")