# -*- coding: utf-8 -*-
"""
Type definitions and data structures for taint analysis.

This module contains enumerations and data classes used throughout
the taint analysis framework.

Compatible with Jython 2.7 for Ghidra environment.
"""

# Import Ghidra types with error handling for non-Ghidra environments
try:
    from ghidra.program.model.pcode import HighVariable
except ImportError:
    # For development/testing outside Ghidra
    HighVariable = None


class TaintType(object):
    """Enumeration of different taint types for fine-grained tracking."""
    RETURN_VALUE = "RETURN_VALUE"
    ARGUMENT = "ARGUMENT"
    MEMORY = "MEMORY"
    REGISTER = "REGISTER"
    CONSTANT = "CONSTANT"
    DERIVED = "DERIVED"
    INDIRECT = "INDIRECT"
    PROPAGATED = "PROPAGATED"


class UsageType(object):
    """Enumeration of different usage types for taint reporting."""
    # Function call related
    TAINTED_ARG_TO_CALL = "TAINTED_ARG_TO_CALL"
    TAINTED_ARG_TO_CALL_RECURSION = "TAINTED_ARG_TO_CALL_RECURSION"
    TAINTED_ARG_TO_UNRESOLVED_CALL = "TAINTED_ARG_TO_UNRESOLVED_CALL"
    TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS = "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS"
    TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP = "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP"
    
    # Return values
    RETURN_TAINTED_VALUE = "RETURN_TAINTED_VALUE"
    TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN = "TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN"
    TAINT_PROPAGATED_FROM_HOST_CALL_RETURN = "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN"
    
    # Memory operations
    TAINTED_MEMORY_ACCESS = "TAINTED_MEMORY_ACCESS"
    TAINTED_POINTER_DEALLOCATED = "TAINTED_POINTER_DEALLOCATED"
    TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG = "TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG"
    
    # Control flow
    BRANCH_CONDITION_TAINTED = "BRANCH_CONDITION_TAINTED"
    TAINTED_COMPARISON = "TAINTED_COMPARISON"
    
    # Special propagation
    TAINT_PROPAGATED_BY_RULE = "TAINT_PROPAGATED_BY_RULE"
    EXPLORING_INITIALLY_UNRESOLVED_CALL = "EXPLORING_INITIALLY_UNRESOLVED_CALL"
    TAINT_PROPAGATED_FROM_CONSTRUCTOR_SINK = "TAINT_PROPAGATED_FROM_CONSTRUCTOR_SINK"
    STORE_TAINTED_VALUE = "STORE_TAINTED_VALUE"
    
    # Custom usage
    CUSTOM = "CUSTOM"


class TaintedVariable(object):
    """
    Represents a tainted variable with metadata.
    
    Attributes:
        high_variable: The Ghidra HighVariable that is tainted
        taint_type: The type of taint (how it became tainted)
        origin: String describing where the taint originated
        representation: Human-readable representation of the variable
        metadata: Additional metadata about the taint
    """
    
    def __init__(self, high_variable, taint_type, origin, representation, metadata=None):
        """
        Initialize TaintedVariable.
        
        Args:
            high_variable: The Ghidra HighVariable
            taint_type: TaintType value
            origin: String describing origin
            representation: String representation
            metadata: Optional dict of metadata
        """
        self.high_variable = high_variable
        self.taint_type = taint_type
        self.origin = origin
        self.representation = representation
        self.metadata = metadata if metadata is not None else {}
    
    def __hash__(self):
        """Make TaintedVariable hashable for use in sets."""
        return hash((id(self.high_variable), self.taint_type, self.origin))
    
    def __eq__(self, other):
        """Equality comparison for TaintedVariable."""
        if not isinstance(other, TaintedVariable):
            return False
        return (self.high_variable == other.high_variable and 
                self.taint_type == other.taint_type and
                self.origin == other.origin)
    
    def __repr__(self):
        """String representation for debugging."""
        return "TaintedVariable({}, {}, {})".format(
            self.representation, self.taint_type, self.origin)


class TaintUsage(object):
    """
    Represents a usage of tainted data.
    
    Attributes:
        originating_function: The function where taint originated
        function_name: The function where the usage occurs
        function_entry: Entry point address of the function
        address: Address where the usage occurs
        pcode_op: String representation of the P-code operation
        usage_type: Type of usage
        tainted_component: Representation of the tainted component
        details: Human-readable description of the usage
        metadata: Additional metadata about the usage
    """
    
    def __init__(self, originating_function, function_name, function_entry,
                 address, pcode_op, usage_type, tainted_component, 
                 details, metadata=None):
        """
        Initialize TaintUsage.
        
        Args:
            originating_function: Origin function name
            function_name: Function where usage occurs
            function_entry: Entry address
            address: Usage address
            pcode_op: P-code operation string
            usage_type: UsageType value
            tainted_component: Tainted component representation
            details: Description
            metadata: Optional metadata dict
        """
        self.originating_function = originating_function
        self.function_name = function_name
        self.function_entry = function_entry
        self.address = address
        self.pcode_op = pcode_op
        self.usage_type = usage_type
        self.tainted_component = tainted_component
        self.details = details
        self.metadata = metadata if metadata is not None else {}
        
        # Store additional attributes that might be added
        self.origin = originating_function  # Alias for compatibility
    
    def to_dict(self):
        """Convert TaintUsage to dictionary for JSON serialization."""
        return {
            "originating_imported_function_name": self.originating_function,
            "found_in_function_name": self.function_name,
            "found_in_function_entry": self.function_entry,
            "instruction_address": self.address,
            "pcode_operation": self.pcode_op,
            "usage_type": self.usage_type if isinstance(self.usage_type, str) else self.usage_type,
            "tainted_component": self.tainted_component,
            "details": self.details
        }
    
    def __repr__(self):
        """String representation for debugging."""
        return "TaintUsage({} at {}: {})".format(
            self.usage_type, self.address, self.details)