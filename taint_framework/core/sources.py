# -*- coding: utf-8 -*-
"""
Simplified taint source definitions for Jython 2.7 compatibility.
"""


class TaintSource(object):
    """Abstract base class for taint sources."""
    
    def is_source(self, function):
        """Check if function is a taint source."""
        return False
    
    def get_tainted_output(self, pcode_op):
        """Get the tainted output from a source operation."""
        return pcode_op.getOutput() if pcode_op else None
    
    def get_source_name(self):
        """Get descriptive name for this source."""
        return "TaintSource"


class KeywordTaintSource(TaintSource):
    """Taint source based on function name keyword matching."""
    
    def __init__(self, keyword, match_type="contains"):
        """
        Initialize keyword-based taint source.
        
        Args:
            keyword: The keyword to match
            match_type: How to match - "contains", "equals", "startswith", "endswith"
        """
        self.keyword = keyword
        self.match_type = match_type.lower()
    
    def is_source(self, function):
        """Check if function name matches the keyword."""
        if not function:
            return False
        
        name = function.getName()
        
        if self.match_type == "contains":
            return self.keyword in name
        elif self.match_type == "equals":
            return name == self.keyword
        elif self.match_type == "startswith":
            return name.startswith(self.keyword)
        elif self.match_type == "endswith":
            return name.endswith(self.keyword)
        
        return False
    
    def get_source_name(self):
        """Return descriptive name."""
        return "Keyword[{}:{}]".format(self.keyword, self.match_type)


class APITaintSource(TaintSource):
    """Taint source for specific API functions."""
    
    def __init__(self, api_names):
        """
        Initialize API-based taint source.
        
        Args:
            api_names: Set of API function names
        """
        self.api_names = api_names if isinstance(api_names, set) else set(api_names)
    
    def is_source(self, function):
        """Check if function is one of the APIs."""
        return function and function.getName() in self.api_names
    
    def get_source_name(self):
        """Return descriptive name."""
        if len(self.api_names) <= 3:
            return "API[{}]".format(", ".join(self.api_names))
        else:
            return "API[{} functions]".format(len(self.api_names))