# -*- coding: utf-8 -*-
"""
Simplified taint rules for Jython 2.7 compatibility.
"""


class TaintRule(object):
    """Abstract base class for custom taint rules."""
    
    def applies_to(self, pcode_op):
        """Check if this rule applies to the given operation."""
        return False
    
    def apply(self, context, pcode_op):
        """Apply the rule to propagate taint."""
        pass
    
    def get_rule_name(self):
        """Get descriptive name for this rule."""
        return "TaintRule"


class MemcpyRule(TaintRule):
    """Taint rule for memory copy operations."""
    
    def applies_to(self, pcode_op):
        """Check if this is a memcpy-like operation."""
        if not pcode_op or pcode_op.getMnemonic() != "CALL":
            return False
        
        # Would need to check if the called function is memcpy/memmove/etc
        return False
    
    def apply(self, context, pcode_op):
        """Apply memcpy taint propagation."""
        # Would propagate taint from source to destination
        pass
    
    def get_rule_name(self):
        """Return descriptive name."""
        return "MemcpyRule"


class MathFunctionRule(TaintRule):
    """Taint rule for mathematical functions."""
    
    def __init__(self, function_names=None):
        """
        Initialize math function rule.
        
        Args:
            function_names: Set of math function names to track
        """
        self.function_names = function_names if function_names else set()
    
    def applies_to(self, pcode_op):
        """Check if this is a math function call."""
        if not pcode_op or pcode_op.getMnemonic() != "CALL":
            return False
        
        # Would need to check if the called function is in our list
        return False
    
    def apply(self, context, pcode_op):
        """Apply math function taint propagation."""
        # Would propagate taint from arguments to return value
        pass
    
    def get_rule_name(self):
        """Return descriptive name."""
        return "MathFunctionRule[{} functions]".format(len(self.function_names))


class CustomPropagationRule(TaintRule):
    """Custom user-defined propagation rule."""
    
    def __init__(self, condition_fn=None, action_fn=None, name="Custom"):
        """
        Initialize custom rule.
        
        Args:
            condition_fn: Function that returns True if rule applies
            action_fn: Function that performs the taint propagation
            name: Descriptive name for the rule
        """
        self.condition_fn = condition_fn
        self.action_fn = action_fn
        self.name = name
    
    def applies_to(self, pcode_op):
        """Check if custom condition is met."""
        if self.condition_fn:
            return self.condition_fn(pcode_op)
        return False
    
    def apply(self, context, pcode_op):
        """Apply custom action."""
        if self.action_fn:
            self.action_fn(context, pcode_op)
    
    def get_rule_name(self):
        """Return descriptive name."""
        return "CustomRule[{}]".format(self.name)