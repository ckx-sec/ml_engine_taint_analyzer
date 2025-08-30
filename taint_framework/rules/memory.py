# -*- coding: utf-8 -*-
"""
Memory operation taint propagation rules.

This module contains rules for handling taint propagation through
memory operations like memcpy, memmove, strcpy, etc.
"""

from typing import Set, Tuple

from ..core.rules import TaintRule
from ..core.types import TaintedVariable, TaintType

# Import Ghidra types with error handling
try:
    from ghidra.program.model.pcode import PcodeOp
except ImportError:
    PcodeOp = None


class MemcpyTaintRule(TaintRule):
    """Rule for propagating taint through memory copy operations."""
    
    def __init__(self):
        """Initialize memcpy taint rule."""
        self.function_names = {"memcpy", "memmove", "bcopy"}
    
    def applies_to(self, pcode_op: PcodeOp, analyzer) -> bool:
        """Check if this is a memory copy function."""
        if pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
            return False
        
        func = analyzer.get_called_function(pcode_op)
        return func and func.getName() in self.function_names
    
    def propagate(self, pcode_op: PcodeOp, tainted_vars: Set[TaintedVariable], 
                 analyzer) -> Tuple[bool, Set[TaintedVariable]]:
        """Propagate taint from source to destination."""
        new_tainted = set()
        
        # memcpy signature: void* memcpy(void* dest, const void* src, size_t n)
        # P-code inputs: [call_target, dest, src, size]
        if pcode_op.getNumInputs() >= 3:
            dest_vn = pcode_op.getInput(1)
            src_vn = pcode_op.getInput(2)
            
            # Check if source is tainted
            src_hv = src_vn.getHigh() if src_vn else None
            if src_hv and any(tv.high_variable == src_hv for tv in tainted_vars):
                # Taint destination
                dest_hv = dest_vn.getHigh() if dest_vn else None
                if dest_hv and not any(tv.high_variable == dest_hv for tv in tainted_vars):
                    func = analyzer.get_called_function(pcode_op)
                    func_name = func.getName() if func else "memcpy"
                    
                    new_var = TaintedVariable(
                        high_variable=dest_hv,
                        taint_type=TaintType.DERIVED,
                        origin=f"{self.get_rule_name()}",
                        representation=analyzer.get_varnode_representation(dest_hv),
                        metadata={
                            "rule": self.get_rule_name(),
                            "function": func_name,
                            "source": analyzer.get_varnode_representation(src_hv)
                        }
                    )
                    new_tainted.add(new_var)
                    
                    if analyzer.config.verbose:
                        analyzer.println(f"[{self.get_rule_name()}] Tainted destination via {func_name}")
        
        # Also check if return value should be tainted (memcpy returns dest)
        output = pcode_op.getOutput()
        if output and output.getHigh() and new_tainted:
            output_hv = output.getHigh()
            if not any(tv.high_variable == output_hv for tv in tainted_vars):
                new_var = TaintedVariable(
                    high_variable=output_hv,
                    taint_type=TaintType.DERIVED,
                    origin=f"{self.get_rule_name()}_return",
                    representation=analyzer.get_varnode_representation(output_hv),
                    metadata={"rule": self.get_rule_name()}
                )
                new_tainted.add(new_var)
        
        return True, new_tainted  # Handled, don't recurse
    
    def get_rule_name(self) -> str:
        """Return rule name."""
        return "MemcpyRule"
    
    def get_priority(self) -> int:
        """Higher priority for memory operations."""
        return 10


class StrcpyTaintRule(TaintRule):
    """Rule for propagating taint through string copy operations."""
    
    def __init__(self):
        """Initialize strcpy taint rule."""
        self.function_names = {"strcpy", "strncpy", "stpcpy", "stpncpy"}
    
    def applies_to(self, pcode_op: PcodeOp, analyzer) -> bool:
        """Check if this is a string copy function."""
        if pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
            return False
        
        func = analyzer.get_called_function(pcode_op)
        return func and func.getName() in self.function_names
    
    def propagate(self, pcode_op: PcodeOp, tainted_vars: Set[TaintedVariable], 
                 analyzer) -> Tuple[bool, Set[TaintedVariable]]:
        """Propagate taint from source string to destination."""
        new_tainted = set()
        
        # strcpy signature: char* strcpy(char* dest, const char* src)
        # P-code inputs: [call_target, dest, src]
        if pcode_op.getNumInputs() >= 3:
            dest_vn = pcode_op.getInput(1)
            src_vn = pcode_op.getInput(2)
            
            # Check if source is tainted
            src_hv = src_vn.getHigh() if src_vn else None
            if src_hv and any(tv.high_variable == src_hv for tv in tainted_vars):
                # Taint destination
                dest_hv = dest_vn.getHigh() if dest_vn else None
                if dest_hv and not any(tv.high_variable == dest_hv for tv in tainted_vars):
                    func = analyzer.get_called_function(pcode_op)
                    func_name = func.getName() if func else "strcpy"
                    
                    new_var = TaintedVariable(
                        high_variable=dest_hv,
                        taint_type=TaintType.DERIVED,
                        origin=f"{self.get_rule_name()}",
                        representation=analyzer.get_varnode_representation(dest_hv),
                        metadata={
                            "rule": self.get_rule_name(),
                            "function": func_name,
                            "source": analyzer.get_varnode_representation(src_hv)
                        }
                    )
                    new_tainted.add(new_var)
        
        # strcpy returns dest pointer
        output = pcode_op.getOutput()
        if output and output.getHigh() and new_tainted:
            output_hv = output.getHigh()
            if not any(tv.high_variable == output_hv for tv in tainted_vars):
                new_var = TaintedVariable(
                    high_variable=output_hv,
                    taint_type=TaintType.DERIVED,
                    origin=f"{self.get_rule_name()}_return",
                    representation=analyzer.get_varnode_representation(output_hv),
                    metadata={"rule": self.get_rule_name()}
                )
                new_tainted.add(new_var)
        
        return True, new_tainted  # Handled, don't recurse
    
    def get_rule_name(self) -> str:
        """Return rule name."""
        return "StrcpyRule"
    
    def get_priority(self) -> int:
        """Higher priority for string operations."""
        return 10


class MemsetTaintRule(TaintRule):
    """Rule for handling memset operations with tainted values."""
    
    def __init__(self):
        """Initialize memset taint rule."""
        self.function_names = {"memset", "bzero"}
    
    def applies_to(self, pcode_op: PcodeOp, analyzer) -> bool:
        """Check if this is a memset function."""
        if pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
            return False
        
        func = analyzer.get_called_function(pcode_op)
        return func and func.getName() in self.function_names
    
    def propagate(self, pcode_op: PcodeOp, tainted_vars: Set[TaintedVariable], 
                 analyzer) -> Tuple[bool, Set[TaintedVariable]]:
        """Propagate taint if the value being set is tainted."""
        new_tainted = set()
        func = analyzer.get_called_function(pcode_op)
        func_name = func.getName() if func else "memset"
        
        if func_name == "memset":
            # memset signature: void* memset(void* ptr, int value, size_t n)
            # P-code inputs: [call_target, ptr, value, size]
            if pcode_op.getNumInputs() >= 3:
                ptr_vn = pcode_op.getInput(1)
                value_vn = pcode_op.getInput(2)
                
                # Check if value is tainted
                value_hv = value_vn.getHigh() if value_vn else None
                if value_hv and any(tv.high_variable == value_hv for tv in tainted_vars):
                    # Taint the memory region (through ptr)
                    ptr_hv = ptr_vn.getHigh() if ptr_vn else None
                    if ptr_hv and not any(tv.high_variable == ptr_hv for tv in tainted_vars):
                        new_var = TaintedVariable(
                            high_variable=ptr_hv,
                            taint_type=TaintType.DERIVED,
                            origin=f"{self.get_rule_name()}",
                            representation=analyzer.get_varnode_representation(ptr_hv),
                            metadata={
                                "rule": self.get_rule_name(),
                                "function": func_name,
                                "tainted_value": analyzer.get_varnode_representation(value_hv)
                            }
                        )
                        new_tainted.add(new_var)
        
        elif func_name == "bzero":
            # bzero just zeroes memory, no taint propagation needed
            pass
        
        # memset returns the pointer
        output = pcode_op.getOutput()
        if output and output.getHigh() and new_tainted:
            output_hv = output.getHigh()
            if not any(tv.high_variable == output_hv for tv in tainted_vars):
                new_var = TaintedVariable(
                    high_variable=output_hv,
                    taint_type=TaintType.DERIVED,
                    origin=f"{self.get_rule_name()}_return",
                    representation=analyzer.get_varnode_representation(output_hv),
                    metadata={"rule": self.get_rule_name()}
                )
                new_tainted.add(new_var)
        
        return True, new_tainted  # Handled, don't recurse
    
    def get_rule_name(self) -> str:
        """Return rule name."""
        return "MemsetRule"


class AllMemoryRules(TaintRule):
    """Composite rule that includes all memory-related rules."""
    
    def __init__(self):
        """Initialize with all memory rules."""
        self.rules = [
            MemcpyTaintRule(),
            StrcpyTaintRule(),
            MemsetTaintRule()
        ]
    
    def applies_to(self, pcode_op: PcodeOp, analyzer) -> bool:
        """Check if any memory rule applies."""
        return any(rule.applies_to(pcode_op, analyzer) for rule in self.rules)
    
    def propagate(self, pcode_op: PcodeOp, tainted_vars: Set[TaintedVariable], 
                 analyzer) -> Tuple[bool, Set[TaintedVariable]]:
        """Apply the first matching rule."""
        for rule in self.rules:
            if rule.applies_to(pcode_op, analyzer):
                return rule.propagate(pcode_op, tainted_vars, analyzer)
        return False, set()
    
    def get_rule_name(self) -> str:
        """Return rule name."""
        return "AllMemoryRules"
    
    def get_priority(self) -> int:
        """High priority for memory operations."""
        return 10