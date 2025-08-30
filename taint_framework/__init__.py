# -*- coding: utf-8 -*-
"""
Modular Taint Analysis Framework for Ghidra

A flexible and extensible framework for tracking data flow through binary programs.
"""

from .core.types import TaintType, UsageType, TaintedVariable, TaintUsage
from .core.sources import TaintSource, KeywordTaintSource
from .core.sinks import TaintSink, FunctionCallSink
from .core.rules import TaintRule
from .core.policies import PropagationPolicy, ExtendedPropagationPolicy
from .core.state import TaintState, AnalysisConfig
from .core.analyzer import TaintAnalyzer

__all__ = [
    # Types
    'TaintType', 'UsageType', 'TaintedVariable', 'TaintUsage',
    # Core components
    'TaintSource', 'KeywordTaintSource',
    'TaintSink', 'FunctionCallSink', 
    'TaintRule',
    'PropagationPolicy', 'ExtendedPropagationPolicy',
    'TaintState', 'AnalysisConfig',
    'TaintAnalyzer'
]

__version__ = '2.0.0'