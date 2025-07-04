# analyze_mnn_taint_modular.py
# An MNN-specific taint analysis script that uses the generic taint engine.
# It defines MNN-specific heuristics and injects them into the generic analyzer.

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

from generic_taint_analyzer import TaintAnalyzer

import sys

# Attempt to import the generic analyzer.
# This allows the script to be self-contained for simple distribution,
# while still benefiting from a modular structure.
try:
    from generic_taint_analyzer import TaintAnalyzer
except ImportError:
    print("ERROR: Could not find 'generic_taint_analyzer.py'.")
    print("Please ensure it is in the same directory as this script or in Ghidra's script paths.")
    sys.exit(1)


def mnn_special_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Handles the MNN-specific taint propagation rule for copyToHostTensor -> host<...>.
    
    This function has the exact signature required by the generic analyzer's rule handler system.
    
    :return: True if the rule was applied and the generic engine should skip this op, False otherwise.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)

    if not called_function_obj:
        return False

    is_copy_to_host_tensor = "copyToHostTensor" in called_function_obj.getName()
    if not is_copy_to_host_tensor:
        return False

    copy_this_ptr_vn = current_pcode_op.getInput(1) if current_pcode_op.getNumInputs() > 1 else None
    if not copy_this_ptr_vn:
        return False
        
    copy_this_ptr_hv = copy_this_ptr_vn.getHigh()
    if not (copy_this_ptr_hv and copy_this_ptr_hv in tainted_hvs):
        return False

    # --- Rule logic starts here ---
    analyzer.println("INFO: [MNN_RULE] Found call to 'copyToHostTensor' with a tainted 'this' pointer: {}".format(
        analyzer._get_varnode_representation(copy_this_ptr_hv, high_func)
    ))

    found_host_call = False
    # Scan forward from the current operation
    for forward_idx in range(op_idx + 1, len(all_pcode_ops)):
        next_op = all_pcode_ops[forward_idx]
        if next_op.getMnemonic() in ["CALL", "CALLIND"]:
            next_called_func = analyzer._get_called_function_from_pcode_op(next_op)
            
            # HEURISTIC: If we find a call to host<...> shortly after a tainted copyToHostTensor,
            # we assume it's the corresponding call and taint its result.
            if next_called_func and "host<" in next_called_func.getName():
                analyzer.println("INFO: [MNN_RULE] SUCCESS! Found subsequent call to '{}' and applying heuristic.".format(
                    next_called_func.getName()
                ))
                
                host_call_output_vn = next_op.getOutput()
                if host_call_output_vn:
                    host_call_output_hv = host_call_output_vn.getHigh()
                    if host_call_output_hv and host_call_output_hv not in tainted_hvs:
                        tainted_hvs.add(host_call_output_hv)
                        output_hv_repr = analyzer._get_varnode_representation(host_call_output_hv, high_func)
                        tainted_hvs_repr.add(output_hv_repr)
                        
                        analyzer.println("DEBUG: [MNN_RULE] Tainting return value of {}: {}".format(next_called_func.getName(), output_hv_repr))
                        analyzer.all_tainted_usages.append({
                            "originating_imported_function_name": origin_log_name,
                            "function_name": high_func.getFunction().getName(),
                            "function_entry": high_func.getFunction().getEntryPoint().toString(),
                            "address": next_op.getSeqnum().getTarget().toString(),
                            "pcode_op_str": str(next_op),
                            "usage_type": "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN",
                            "tainted_component_repr": output_hv_repr,
                            "details": "Return of '{}' tainted due to 'copyToHostTensor' MNN-specific heuristic.".format(next_called_func.getName())
                        })
                found_host_call = True
                break # Stop scanning forward
    
    if not found_host_call:
        analyzer.println("INFO: [MNN_RULE] Forward scan for 'host<...>' completed, but no matching call was found.")

    # We must halt further processing for this op to prevent default recursion into copyToHostTensor.
    analyzer.println("INFO: [MNN_RULE] Halting analysis for this PCodeOp to prevent recursion into 'copyToHostTensor'.")
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
        # Register the MNN-specific rule handler with the generic analyzer.
        mnn_rules = [mnn_special_rule_handler]

        analyzer = TaintAnalyzer(
            current_program=_current_program,
            monitor=_monitor,
            println=_println,
            printerr=_printerr,
            askFile=_askFile,
            rule_handlers=mnn_rules
        )
        target_api_keyword = "getSessionOutput"
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
    _final_println("MNN Taint Analyzer finished.") 