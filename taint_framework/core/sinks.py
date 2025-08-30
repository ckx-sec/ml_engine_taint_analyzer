# -*- coding: utf-8 -*-
"""
Simplified taint sink definitions for Jython 2.7 compatibility.
"""


class TaintSink(object):
    """Abstract base class for taint sinks."""
    
    def is_sink(self, pcode_op):
        """Check if this operation is a sink."""
        return False
    
    def handle_tainted_sink(self, context, pcode_op, tainted_inputs):
        """Handle when tainted data reaches a sink."""
        return True


class FunctionCallSink(TaintSink):
    """Sink for function calls with tainted arguments."""
    
    def __init__(self, function_names=None, track_args=True, track_return=False):
        """
        Initialize function call sink.
        
        Args:
            function_names: Set of function names to track
            track_args: Track tainted arguments
            track_return: Track tainted returns
        """
        self.function_names = function_names if function_names else set()
        self.track_args = track_args
        self.track_return = track_return
    
    def is_sink(self, pcode_op):
        """Check if this is a call to a tracked function."""
        if not pcode_op:
            return False
        return pcode_op.getMnemonic() in ["CALL", "CALLIND"]
    
    def handle_tainted_sink(self, context, pcode_op, tainted_inputs):
        """Handle tainted call."""
        # This would be implemented to track the tainted call
        return True


class DeallocationSink(TaintSink):
    """Sink for memory deallocation functions."""
    
    def __init__(self):
        """Initialize deallocation sink."""
        self.dealloc_functions = {"free", "delete", "_free", "_delete"}
    
    def is_sink(self, pcode_op):
        """Check if this is a deallocation."""
        if not pcode_op or pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
            return False
        # Would need to check if the called function is a deallocation
        return False


class MemoryAccessSink(TaintSink):
    """Sink for memory access with tainted pointers."""
    
    def is_sink(self, pcode_op):
        """Check if this is a memory access."""
        if not pcode_op:
            return False
        return pcode_op.getMnemonic() in ["LOAD", "STORE"]


class BranchConditionSink(TaintSink):
    """Sink for conditional branches with tainted conditions."""
    
    def is_sink(self, pcode_op):
        """Check if this is a conditional branch."""
        if not pcode_op:
            return False
        return pcode_op.getMnemonic() == "CBRANCH"