# -*- coding: utf-8 -*-
"""
Simplified propagation policies for Jython 2.7 compatibility.
"""


class PropagationPolicy(object):
    """Base class for taint propagation policies."""
    
    def should_propagate(self, pcode_op):
        """Determine if taint should propagate through this operation."""
        if not pcode_op:
            return False
        
        mnemonic = pcode_op.getMnemonic()
        
        # Basic propagation rules
        if mnemonic in ["COPY", "CAST", "INT_ZEXT", "INT_SEXT", "INT2FLOAT", "FLOAT2FLOAT"]:
            return True
        
        # Arithmetic operations
        if mnemonic in ["INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_REM",
                        "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV"]:
            return True
        
        # Bitwise operations  
        if mnemonic in ["INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT"]:
            return True
        
        # Memory operations
        if mnemonic in ["LOAD", "STORE"]:
            return True
        
        # PHI nodes
        if mnemonic == "MULTIEQUAL":
            return True
        
        return False
    
    def get_propagation_type(self, pcode_op):
        """Get the type of propagation for this operation."""
        if not pcode_op:
            return "NONE"
        
        mnemonic = pcode_op.getMnemonic()
        
        if mnemonic in ["COPY", "CAST", "MULTIEQUAL"]:
            return "DIRECT"
        elif mnemonic in ["LOAD", "STORE"]:
            return "MEMORY"
        elif mnemonic.startswith("INT_") or mnemonic.startswith("FLOAT_"):
            return "ARITHMETIC"
        
        return "UNKNOWN"
    
    def propagate(self, context, pcode_op, tainted_inputs):
        """
        Propagate taint through the operation.
        
        Args:
            context: The analysis context
            pcode_op: The P-code operation
            tainted_inputs: List of tainted input varnodes
        
        Returns:
            List of newly tainted varnodes
        """
        if not self.should_propagate(pcode_op):
            return []
        
        output = pcode_op.getOutput()
        if output and output.getHigh():
            # Mark output as tainted in the context
            return [output]
        
        return []


class ExtendedPropagationPolicy(PropagationPolicy):
    """Extended propagation policy with additional operations."""
    
    def __init__(self, include_comparisons=True, include_indirect=True):
        """
        Initialize extended policy.
        
        Args:
            include_comparisons: Include comparison operations
            include_indirect: Include indirect operations
        """
        self.include_comparisons = include_comparisons
        self.include_indirect = include_indirect
    
    def should_propagate(self, pcode_op):
        """Extended propagation check."""
        # Start with base policy
        if PropagationPolicy.should_propagate(self, pcode_op):
            return True
        
        if not pcode_op:
            return False
        
        mnemonic = pcode_op.getMnemonic()
        
        # Comparison operations
        if self.include_comparisons:
            if mnemonic in ["INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL",
                          "INT_SLESS", "INT_SLESSEQUAL", "FLOAT_EQUAL", "FLOAT_NOTEQUAL",
                          "FLOAT_LESS", "FLOAT_LESSEQUAL"]:
                return True
        
        # Indirect operations
        if self.include_indirect:
            if mnemonic in ["INDIRECT", "CALLIND", "BRANCHIND"]:
                return True
        
        return False


class StrictPropagationPolicy(PropagationPolicy):
    """Strict propagation policy that only allows direct data flow."""
    
    def should_propagate(self, pcode_op):
        """Only allow direct data movement."""
        if not pcode_op:
            return False
        
        mnemonic = pcode_op.getMnemonic()
        
        # Only direct copies and casts
        return mnemonic in ["COPY", "CAST", "MULTIEQUAL"]
    
    def get_propagation_type(self, pcode_op):
        """Always return DIRECT for strict policy."""
        if self.should_propagate(pcode_op):
            return "DIRECT"
        return "NONE"