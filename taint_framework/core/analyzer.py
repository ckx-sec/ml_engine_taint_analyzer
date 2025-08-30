# -*- coding: utf-8 -*-
"""
Taint analyzer for Jython 2.7 compatibility.

This is a bridge between the base.py analyzer and the modular framework.
It provides the essential TaintAnalyzer class that framework-based analyzers expect.
"""

import json
import os
import sys

# Import the base analyzer that we know works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
try:
    from base import TaintAnalyzer as BaseTaintAnalyzer
except ImportError:
    # Try alternate import
    import base
    BaseTaintAnalyzer = base.TaintAnalyzer


class TaintAnalyzer(BaseTaintAnalyzer):
    """
    Simplified TaintAnalyzer that wraps base.py functionality.
    
    This provides compatibility with the taint_framework interface
    while using the proven base.py implementation.
    """
    
    def __init__(self, current_program, monitor, println, printerr, askFile=None):
        """Initialize the analyzer."""
        BaseTaintAnalyzer.__init__(self, current_program, monitor, println, printerr, askFile)
        
        # Additional framework-specific attributes
        self.sources = []
        self.sinks = []
        self.rules = []
        self.propagation_policy = None
        
    def add_source(self, source):
        """Add a taint source (for framework compatibility)."""
        self.sources.append(source)
        
    def add_sink(self, sink):
        """Add a taint sink (for framework compatibility)."""
        self.sinks.append(sink)
        
    def add_rule(self, rule):
        """Add a custom rule (for framework compatibility)."""
        self.rules.append(rule)
        
    def set_propagation_policy(self, policy):
        """Set propagation policy (for framework compatibility)."""
        self.propagation_policy = policy
        
    def configure(self, **kwargs):
        """Configure the analyzer."""
        # Map framework config to base.py config
        if 'max_recursion_depth' in kwargs:
            self.MAX_RECURSION_DEPTH = kwargs['max_recursion_depth']
        if 'verbose' in kwargs:
            self.verbose = kwargs['verbose']
        if 'track_memory_regions' in kwargs:
            self.track_memory_regions = kwargs['track_memory_regions']
        if 'follow_indirect_calls' in kwargs:
            self.follow_indirect_calls = kwargs['follow_indirect_calls']
            
    def analyze(self):
        """
        Run the analysis using the configured sources.
        
        This method bridges between the framework interface and base.py.
        """
        # If we have keyword sources, use the first one
        if self.sources:
            for source in self.sources:
                if hasattr(source, 'keyword'):
                    # Run base.py analysis with this keyword
                    self.run(source.keyword)
                    break
        
        # Return results in framework format
        return self
    
    def get_results(self):
        """Get analysis results in framework format."""
        return self
    
    def get_usages(self):
        """Get taint usages from the analysis."""
        # Convert base.py format to framework format
        usages = []
        for usage in self.all_tainted_usages:
            # Create a simple object with the needed attributes
            class SimpleUsage(object):
                def __init__(self, data):
                    self.originating_function = data.get("originating_imported_function_name", "")
                    self.function_name = data.get("function_name", "")
                    self.function_entry = data.get("function_entry", "")
                    self.address = data.get("address", "")
                    self.pcode_op = data.get("pcode_op_str", "")
                    self.usage_type = data.get("usage_type", "")
                    self.tainted_component = data.get("tainted_component_repr", "")
                    self.details = data.get("details", "")
                    self.origin = self.originating_function
            
            usages.append(SimpleUsage(usage))
        
        return usages
    
    def get_called_function(self, pcode_op):
        """Get the function called by a P-code operation."""
        return self._get_called_function_from_pcode_op(pcode_op)
    
    def is_tainted(self, varnode):
        """Check if a varnode is tainted."""
        if not varnode:
            return False
        high_var = varnode.getHigh()
        if not high_var:
            return False
        # Check if in tainted set (base.py uses sets of high variables)
        # This is a simplified check - the actual implementation in base.py is more complex
        return False  # Simplified for now
    
    def add_taint(self, high_var, taint_type, origin):
        """Add a variable to the tainted set."""
        # This would need to integrate with base.py's taint tracking
        pass
    
    def report_usage(self, usage_type, pcode_op=None, details=""):
        """Report a taint usage."""
        # Add to base.py's usage tracking
        if pcode_op:
            self.all_tainted_usages.append({
                "originating_imported_function_name": self.target_keyword if hasattr(self, 'target_keyword') else "",
                "function_name": "unknown",
                "function_entry": "unknown",
                "address": str(pcode_op.getSeqnum().getTarget()) if pcode_op else "unknown",
                "pcode_op_str": str(pcode_op) if pcode_op else "",
                "usage_type": usage_type,
                "details": details
            })