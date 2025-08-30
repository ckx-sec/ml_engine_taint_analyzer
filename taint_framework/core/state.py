# -*- coding: utf-8 -*-
"""
Simplified state management for Jython 2.7 compatibility.
"""


class TaintState(object):
    """Manages taint state during analysis."""
    
    def __init__(self):
        """Initialize taint state."""
        self.tainted_variables = {}  # high_var -> TaintedVariable
        self.tainted_memory = {}     # address -> TaintedVariable
        self.function_summaries = {} # function -> summary
        self.visited_blocks = set()  # visited basic blocks
        self.call_stack = []         # call stack for recursion tracking
    
    def add_tainted_variable(self, high_var, taint_info):
        """Add a tainted variable to the state."""
        if high_var:
            self.tainted_variables[high_var] = taint_info
    
    def is_variable_tainted(self, high_var):
        """Check if a variable is tainted."""
        return high_var in self.tainted_variables
    
    def get_taint_info(self, high_var):
        """Get taint information for a variable."""
        return self.tainted_variables.get(high_var)
    
    def add_tainted_memory(self, address, taint_info):
        """Add tainted memory location."""
        self.tainted_memory[address] = taint_info
    
    def is_memory_tainted(self, address):
        """Check if memory location is tainted."""
        return address in self.tainted_memory
    
    def get_memory_taint(self, address):
        """Get taint info for memory location."""
        return self.tainted_memory.get(address)
    
    def mark_block_visited(self, block_address):
        """Mark a basic block as visited."""
        self.visited_blocks.add(block_address)
    
    def is_block_visited(self, block_address):
        """Check if block has been visited."""
        return block_address in self.visited_blocks
    
    def push_call(self, function):
        """Push function onto call stack."""
        self.call_stack.append(function)
    
    def pop_call(self):
        """Pop function from call stack."""
        if self.call_stack:
            return self.call_stack.pop()
        return None
    
    def get_call_depth(self):
        """Get current call stack depth."""
        return len(self.call_stack)
    
    def clone(self):
        """Create a copy of the current state."""
        new_state = TaintState()
        new_state.tainted_variables = dict(self.tainted_variables)
        new_state.tainted_memory = dict(self.tainted_memory)
        new_state.function_summaries = dict(self.function_summaries)
        new_state.visited_blocks = set(self.visited_blocks)
        new_state.call_stack = list(self.call_stack)
        return new_state
    
    def merge(self, other_state):
        """Merge another state into this one."""
        if other_state:
            self.tainted_variables.update(other_state.tainted_variables)
            self.tainted_memory.update(other_state.tainted_memory)
            self.function_summaries.update(other_state.function_summaries)
            self.visited_blocks.update(other_state.visited_blocks)


class AnalysisConfig(object):
    """Configuration for taint analysis."""
    
    def __init__(self):
        """Initialize with default configuration."""
        self.max_recursion_depth = 20
        self.follow_indirect_calls = True
        self.track_memory_regions = True
        self.verbose = False
        self.explore_unresolved_calls = 3
        self.track_comparisons = True
        self.enable_function_summaries = True
        self.max_path_length = 1000
        self.timeout_seconds = 300
    
    def set_max_recursion(self, depth):
        """Set maximum recursion depth."""
        self.max_recursion_depth = depth
        return self
    
    def set_verbose(self, verbose):
        """Set verbose mode."""
        self.verbose = verbose
        return self
    
    def set_follow_indirect(self, follow):
        """Set whether to follow indirect calls."""
        self.follow_indirect_calls = follow
        return self
    
    def set_track_memory(self, track):
        """Set whether to track memory regions."""
        self.track_memory_regions = track
        return self
    
    def set_explore_unresolved(self, budget):
        """Set budget for exploring unresolved calls."""
        self.explore_unresolved_calls = budget
        return self
    
    def to_dict(self):
        """Convert config to dictionary."""
        return {
            "max_recursion_depth": self.max_recursion_depth,
            "follow_indirect_calls": self.follow_indirect_calls,
            "track_memory_regions": self.track_memory_regions,
            "verbose": self.verbose,
            "explore_unresolved_calls": self.explore_unresolved_calls,
            "track_comparisons": self.track_comparisons,
            "enable_function_summaries": self.enable_function_summaries,
            "max_path_length": self.max_path_length,
            "timeout_seconds": self.timeout_seconds
        }