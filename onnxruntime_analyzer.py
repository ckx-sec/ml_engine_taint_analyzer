# onnxruntime_analyzer.py
# An ONNX Runtime-specific taint analysis script that uses the generic taint engine.
# It defines ONNX Runtime-specific heuristics and injects them into the generic analyzer.

# Ghidra Script Boilerplate
try:
    _current_program = currentProgram
    _current_address = currentAddress
    _monitor = monitor
    _println = println
    _printerr = printerr
    _askFile = askFile
except NameError:
    # This block is for developing outside Ghidra, e.g., with ghidra_bridge.
    # It should not be reached in headless mode.
    import sys
    _current_program = None
    _current_address = None
    _monitor = None
    _println = lambda msg: sys.stdout.write(str(msg) + "\n")
    _printerr = lambda msg: sys.stderr.write(str(msg) + "\n")
    _askFile = None
    # Add script directory to path to allow importing our modules
    import os
    # Assuming the script is in the same directory as generic_taint_analyzer
    sys.path.append(os.path.dirname(os.path.realpath(__file__)))


import sys

# Attempt to import the generic analyzer.
try:
    from generic_taint_analyzer import TaintAnalyzer
except ImportError:
    print("ERROR: Could not find 'generic_taint_analyzer.py'.")
    print("Please ensure it is in the same directory as this script or in Ghidra's script paths.")
    sys.exit(1)


def onnxruntime_special_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Handles the ONNX Runtime-specific taint propagation rule for `Ort::Value` -> `GetTensorData<T>()`.
    
    :return: True if the rule was applied and the generic engine should skip this op, False otherwise.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)

    if not called_function_obj:
        return False

    # Heuristic: Check for the method name that extracts the raw data pointer.
    # This could be GetTensorData, GetTensorMutableData, etc.
    func_name = called_function_obj.getName()
    is_get_data_call = "GetTensorData" in func_name or "GetTensorMutableData" in func_name
    
    if not is_get_data_call:
        return False

    # The 'this' pointer of the method call is the first P-code input.
    get_data_this_ptr_vn = current_pcode_op.getInput(1) if current_pcode_op.getNumInputs() > 1 else None
    if not get_data_this_ptr_vn:
        return False
        
    # Check if the Ort::Value object (`this` pointer) is tainted.
    get_data_this_ptr_hv = get_data_this_ptr_vn.getHigh()
    if not (get_data_this_ptr_hv and get_data_this_ptr_hv in tainted_hvs):
        return False

    # --- Rule logic starts here ---
    analyzer.println("INFO: [ONNX_RULE] Found call to '{}' with a tainted 'this' pointer (Ort::Value): {}".format(
        func_name,
        analyzer._get_varnode_representation(get_data_this_ptr_hv, high_func)
    ))

    # The return value of GetTensorData is the raw data pointer, which should now be tainted.
    get_data_output_vn = current_pcode_op.getOutput()
    if get_data_output_vn:
        get_data_output_hv = get_data_output_vn.getHigh()
        if get_data_output_hv and get_data_output_hv not in tainted_hvs:
            tainted_hvs.add(get_data_output_hv)
            output_hv_repr = analyzer._get_varnode_representation(get_data_output_hv, high_func)
            tainted_hvs_repr.add(output_hv_repr)
            
            analyzer.println("DEBUG: [ONNX_RULE] Tainting return value of {}: {}".format(func_name, output_hv_repr))
            analyzer.all_tainted_usages.append({
                "originating_imported_function_name": origin_log_name,
                "function_name": high_func.getFunction().getName(),
                "function_entry": high_func.getFunction().getEntryPoint().toString(),
                "address": current_pcode_op.getSeqnum().getTarget().toString(),
                "pcode_op_str": str(current_pcode_op),
                "usage_type": "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN", # Re-using a generic type
                "tainted_component_repr": output_hv_repr,
                "details": "Return of '{}' tainted due to ONNX Runtime-specific heuristic.".format(func_name)
            })

    # Halt further generic processing for this op to prevent recursion into GetTensorData.
    analyzer.println("INFO: [ONNX_RULE] Halting analysis for this PCodeOp to prevent recursion into '{}'.".format(func_name))
    return True


# -------------------
# Main script entry point (Ghidra script boilerplate)
# -------------------
def run_analysis_from_ghidra_ui():
    """
    This function is the main entry point when run from Ghidra's UI.
    It sets up the environment and kicks off the analysis.
    """
    if not all((_current_program, _monitor, _println, _printerr, _askFile)):
        sys.stderr.write("Error: This script must be run within a full Ghidra UI environment.\n")
        return

    analyzer = None
    try:
        # With the new strategy, we start tainting from the return of GetTensorData itself,
        # so a special rule handler is no longer needed. The generic engine's default
        # behavior (tainting the return value) is exactly what we want.
        analyzer = TaintAnalyzer(
            current_program=_current_program,
            monitor=_monitor,
            println=_println,
            printerr=_printerr,
            askFile=_askFile,
            rule_handlers=[]  # No special rules needed for this strategy
        )
        
        # New Strategy: Start tainting from the function that extracts the raw data pointer.
        target_api_keyword = "GetTensorData"
        analyzer.run(target_api_keyword)

    except Exception as e:
        import traceback
        _effective_printerr = _printerr if _printerr else lambda msg: sys.stderr.write(str(msg) + "\n")
        _effective_printerr("An unhandled error occurred during TaintAnalyzer setup or execution:")
        _effective_printerr(str(e))
        try:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            for line in tb_lines:
                _effective_printerr(line.rstrip())
        except Exception as p_e:
            _effective_printerr("Error printing traceback: {}".format(p_e))
    finally:
        if analyzer:
            del analyzer

if __name__ == "__main__":
    if 'currentProgram' in globals() and globals().get('currentProgram') is not None:
        run_analysis_from_ghidra_ui()
    else:
        print("This script is designed to be run from within Ghidra's Script Manager.")
    
    _final_println = globals().get('println', lambda x: None)
    _final_println("ONNX Runtime Taint Analyzer finished.")

