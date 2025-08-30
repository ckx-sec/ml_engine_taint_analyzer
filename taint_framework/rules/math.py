# -*- coding: utf-8 -*-
"""
Math library taint propagation rules.

This module contains rules for handling taint propagation through
mathematical functions from the standard C math library.
"""

from typing import Set, Tuple

from ..core.rules import TaintRule
from ..core.types import TaintedVariable, TaintType

# Import Ghidra types with error handling
try:
    from ghidra.program.model.pcode import PcodeOp
except ImportError:
    PcodeOp = None


# Common math functions that propagate taint
MATH_LIB_FUNCTIONS = {
    # Exponential and logarithmic
    "exp", "expf", "expl",
    "exp2", "exp2f", "exp2l",
    "expm1", "expm1f", "expm1l",
    "log", "logf", "logl",
    "log10", "log10f", "log10l",
    "log1p", "log1pf", "log1pl",
    "log2", "log2f", "log2l",
    "logb", "logbf", "logbl",
    
    # Trigonometric
    "sin", "sinf", "sinl",
    "cos", "cosf", "cosl",
    "tan", "tanf", "tanl",
    "asin", "asinf", "asinl",
    "acos", "acosf", "acosl",
    "atan", "atanf", "atanl",
    "atan2", "atan2f", "atan2l",
    
    # Hyperbolic
    "sinh", "sinhf", "sinhl",
    "cosh", "coshf", "coshl",
    "tanh", "tanhf", "tanhl",
    "asinh", "asinhf", "asinhl",
    "acosh", "acoshf", "acoshl",
    "atanh", "atanhf", "atanhl",
    
    # Power and root
    "sqrt", "sqrtf", "sqrtl",
    "cbrt", "cbrtf", "cbrtl",
    "pow", "powf", "powl",
    "hypot", "hypotf", "hypotl",
    
    # Absolute value and sign
    "fabs", "fabsf", "fabsl",
    "copysign", "copysignf", "copysignl",
    
    # Rounding
    "floor", "floorf", "floorl",
    "ceil", "ceilf", "ceill",
    "round", "roundf", "roundl",
    "trunc", "truncf", "truncl",
    "nearbyint", "nearbyintf", "nearbyintl",
    "rint", "rintf", "rintl",
    
    # Remainder
    "fmod", "fmodf", "fmodl",
    "remainder", "remainderf", "remainderl",
    
    # Min/Max
    "fmax", "fmaxf", "fmaxl",
    "fmin", "fminf", "fminl",
    "fdim", "fdimf", "fdiml",
    
    # Manipulation
    "frexp", "frexpf", "frexpl",
    "ldexp", "ldexpf", "ldexpl",
    "modf", "modff", "modfl",
    "scalbn", "scalbnf", "scalbnl",
    "scalbln", "scalblnf", "scalblnl",
    
    # Special functions
    "erf", "erff", "erfl",
    "erfc", "erfcf", "erfcl",
    "tgamma", "tgammaf", "tgammal",
    "lgamma", "lgammaf", "lgammal"
}


class MathLibraryTaintRule(TaintRule):
    """Rule for propagating taint through math library functions."""
    
    def __init__(self, functions: Set[str] = None):
        """
        Initialize math library taint rule.
        
        Args:
            functions: Optional set of function names to handle.
                      Defaults to MATH_LIB_FUNCTIONS.
        """
        self.function_names = functions or MATH_LIB_FUNCTIONS
    
    def applies_to(self, pcode_op: PcodeOp, analyzer) -> bool:
        """Check if this is a math library function."""
        if pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
            return False
        
        func = analyzer.get_called_function(pcode_op)
        return func and func.getName() in self.function_names
    
    def propagate(self, pcode_op: PcodeOp, tainted_vars: Set[TaintedVariable], 
                 analyzer) -> Tuple[bool, Set[TaintedVariable]]:
        """Propagate taint from arguments to return value."""
        new_tainted = set()
        
        # Check if any argument is tainted
        is_any_arg_tainted = False
        tainted_arg_reprs = []
        
        for i in range(1, pcode_op.getNumInputs()):
            arg_vn = pcode_op.getInput(i)
            if arg_vn and arg_vn.getHigh():
                arg_hv = arg_vn.getHigh()
                if any(tv.high_variable == arg_hv for tv in tainted_vars):
                    is_any_arg_tainted = True
                    tainted_arg_reprs.append(analyzer.get_varnode_representation(arg_hv))
        
        if is_any_arg_tainted:
            # Taint the return value
            output_vn = pcode_op.getOutput()
            if output_vn and output_vn.getHigh():
                output_hv = output_vn.getHigh()
                
                # Check if already tainted
                if not any(tv.high_variable == output_hv for tv in tainted_vars):
                    func = analyzer.get_called_function(pcode_op)
                    func_name = func.getName() if func else "math_function"
                    
                    new_var = TaintedVariable(
                        high_variable=output_hv,
                        taint_type=TaintType.DERIVED,
                        origin=f"MathLib[{func_name}]",
                        representation=analyzer.get_varnode_representation(output_hv),
                        metadata={
                            "rule": self.get_rule_name(),
                            "function": func_name,
                            "tainted_args": tainted_arg_reprs,
                            "category": self._get_function_category(func_name)
                        }
                    )
                    new_tainted.add(new_var)
                    
                    if analyzer.config.verbose:
                        analyzer.println(f"[{self.get_rule_name()}] Propagated taint through {func_name}")
        
        return True, new_tainted  # Handled, don't recurse into math functions
    
    def _get_function_category(self, func_name: str) -> str:
        """Categorize the math function."""
        if any(func_name.startswith(prefix) for prefix in ["exp", "log"]):
            return "exponential"
        elif any(func_name.startswith(prefix) for prefix in ["sin", "cos", "tan", "asin", "acos", "atan"]):
            return "trigonometric"
        elif any(func_name.startswith(prefix) for prefix in ["sinh", "cosh", "tanh"]):
            return "hyperbolic"
        elif any(func_name.startswith(prefix) for prefix in ["sqrt", "cbrt", "pow", "hypot"]):
            return "power"
        elif any(func_name.startswith(prefix) for prefix in ["floor", "ceil", "round", "trunc"]):
            return "rounding"
        elif any(func_name.startswith(prefix) for prefix in ["fmod", "remainder"]):
            return "remainder"
        elif any(func_name.startswith(prefix) for prefix in ["fabs", "copysign"]):
            return "absolute"
        elif any(func_name.startswith(prefix) for prefix in ["fmax", "fmin"]):
            return "comparison"
        else:
            return "other"
    
    def get_rule_name(self) -> str:
        """Return rule name."""
        return "MathLibraryRule"
    
    def get_priority(self) -> int:
        """Math functions have medium priority."""
        return 5


class SpecialMathRule(TaintRule):
    """
    Special rule for math functions that might need different handling.
    
    For example, copysign(x, y) only uses the sign of y, so taint
    propagation might be conditional.
    """
    
    def __init__(self):
        """Initialize special math rule."""
        self.special_functions = {
            "copysign", "copysignf", "copysignl",  # Special sign handling
            "isnan", "isinf", "isfinite",  # Boolean predicates
            "signbit", "fpclassify"  # Classification functions
        }
    
    def applies_to(self, pcode_op: PcodeOp, analyzer) -> bool:
        """Check if this is a special math function."""
        if pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
            return False
        
        func = analyzer.get_called_function(pcode_op)
        return func and func.getName() in self.special_functions
    
    def propagate(self, pcode_op: PcodeOp, tainted_vars: Set[TaintedVariable], 
                 analyzer) -> Tuple[bool, Set[TaintedVariable]]:
        """Handle special math functions."""
        new_tainted = set()
        func = analyzer.get_called_function(pcode_op)
        func_name = func.getName() if func else ""
        
        if func_name.startswith("copysign"):
            # copysign(x, y) returns x with sign of y
            # Taint output if first argument is tainted
            if pcode_op.getNumInputs() >= 2:
                x_vn = pcode_op.getInput(1)
                if x_vn and x_vn.getHigh():
                    x_hv = x_vn.getHigh()
                    if any(tv.high_variable == x_hv for tv in tainted_vars):
                        output = pcode_op.getOutput()
                        if output and output.getHigh():
                            output_hv = output.getHigh()
                            if not any(tv.high_variable == output_hv for tv in tainted_vars):
                                new_var = TaintedVariable(
                                    high_variable=output_hv,
                                    taint_type=TaintType.DERIVED,
                                    origin=f"SpecialMath[{func_name}]",
                                    representation=analyzer.get_varnode_representation(output_hv),
                                    metadata={
                                        "rule": self.get_rule_name(),
                                        "function": func_name,
                                        "note": "Magnitude tainted, sign not tainted"
                                    }
                                )
                                new_tainted.add(new_var)
        
        elif func_name in {"isnan", "isinf", "isfinite", "signbit", "fpclassify"}:
            # These are predicates - they return boolean/int based on float properties
            # We might want to track these differently
            # For now, propagate taint normally
            if pcode_op.getNumInputs() >= 2:
                arg_vn = pcode_op.getInput(1)
                if arg_vn and arg_vn.getHigh():
                    arg_hv = arg_vn.getHigh()
                    if any(tv.high_variable == arg_hv for tv in tainted_vars):
                        output = pcode_op.getOutput()
                        if output and output.getHigh():
                            output_hv = output.getHigh()
                            if not any(tv.high_variable == output_hv for tv in tainted_vars):
                                new_var = TaintedVariable(
                                    high_variable=output_hv,
                                    taint_type=TaintType.DERIVED,
                                    origin=f"MathPredicate[{func_name}]",
                                    representation=analyzer.get_varnode_representation(output_hv),
                                    metadata={
                                        "rule": self.get_rule_name(),
                                        "function": func_name,
                                        "type": "predicate"
                                    }
                                )
                                new_tainted.add(new_var)
        
        return True, new_tainted  # Handled
    
    def get_rule_name(self) -> str:
        """Return rule name."""
        return "SpecialMathRule"
    
    def get_priority(self) -> int:
        """Higher priority than general math rule."""
        return 6


class AllMathRules(TaintRule):
    """Composite rule that includes all math-related rules."""
    
    def __init__(self):
        """Initialize with all math rules."""
        # Order matters - special rules should be checked first
        self.rules = [
            SpecialMathRule(),
            MathLibraryTaintRule()
        ]
    
    def applies_to(self, pcode_op: PcodeOp, analyzer) -> bool:
        """Check if any math rule applies."""
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
        return "AllMathRules"
    
    def get_priority(self) -> int:
        """Math operations have medium priority."""
        return 5