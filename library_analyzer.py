from ghidra.program.model.pcode import PcodeOp, Varnode, HighVariable
from ghidra.program.model.listing import Function, Instruction, VariableStorage
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import Pointer
import ghidra.program.model.pcode
import traceback
import sys
import json
import os
import re
from collections import defaultdict

try:
    from generic_taint_analyzer import TaintAnalyzer
except ImportError:
    print("ERROR: Could not find 'generic_taint_analyzer.py'.")
    print("Please ensure it is in the same directory as this script or in Ghidra's script paths.")
    sys.exit(1)


def resolve_comparison_info(analyzer, branch_address_str):
    if not branch_address_str:
        return None

    try:
        branch_address = analyzer.current_program.getAddressFactory().getAddress(branch_address_str)
        current_instruction = analyzer.current_program.getListing().getInstructionAt(branch_address)

        if not current_instruction:
            return None

        search_limit = 10
        prev_instr = current_instruction
        for _ in range(search_limit):
            prev_instr = prev_instr.getPrevious()
            if not prev_instr:
                break

            mnemonic = prev_instr.getMnemonicString().lower()
            comparison_mnemonics = [
                "cmp", "cmn", "tst", "teq", "ccmp", "ccmn", 
                "fcmp", "fcmpe", "cmeq", "cmge", "cmgt", "cmhi", "cmhs"
            ]
            if mnemonic in comparison_mnemonics:
                operands = []
                for i in range(prev_instr.getNumOperands()):
                    operands.append(prev_instr.getDefaultOperandRepresentation(i))
                
                comp_addr_str = prev_instr.getAddress().toString()
                
                result = {
                    "instruction_obj": prev_instr,
                    "address_str": comp_addr_str,
                    "instruction_str": prev_instr.toString(),
                    "operands": operands
                }
                analyzer.println("INFO: [RESOLVER] Resolved branch at {} to comparison instruction '{}' at {}".format(
                    branch_address_str, 
                    result["instruction_str"],
                    result["address_str"]
                ))
                return result
    except Exception as e:
        analyzer.printerr("WARN: [RESOLVER] Failed to resolve comparison info for branch at {}: {}".format(branch_address_str, e))

    analyzer.println("WARN: [RESOLVER] Could not find a comparison instruction for branch at {}.".format(branch_address_str))
    return None


def generate_hook_config(analyzer):
    if not analyzer.all_tainted_usages:
        analyzer.println("No tainted usages found, skipping hook config generation.")
        return

    hook_entries = []
    processed_addresses = set()

    for usage in analyzer.all_tainted_usages:
        if usage.get("usage_type") == "BRANCH_CONDITION_TAINTED":
            address_str = usage.get("address", "N/A")
            
            if address_str == "N/A" or address_str in processed_addresses:
                continue
            processed_addresses.add(address_str)

            branch_target_str = "0x0"
            try:
                instruction_address = analyzer.current_program.getAddressFactory().getAddress(address_str)
                instruction = analyzer.current_program.getListing().getInstructionAt(instruction_address)
                
                if instruction:
                    flow_addresses = instruction.getFlows()
                    fallthrough_addr = instruction.getFallThrough()
                    
                    for addr in flow_addresses:
                        if fallthrough_addr is None or not addr.equals(fallthrough_addr):
                            modified_target_val = addr.getOffset() - 0x100000
                            branch_target_str = "0x{:x}".format(modified_target_val)
                            break
                    
                    if branch_target_str == "0x0" and flow_addresses:
                         analyzer.println("WARN: Could not determine unique branch target for instruction at {}. This may happen for unconditional branches treated as conditional by the decompiler.".format(address_str))
                         if not flow_addresses[0].equals(fallthrough_addr):
                            modified_target_val = flow_addresses[0].getOffset() - 0x100000
                            branch_target_str = "0x{:x}".format(modified_target_val)

                else:
                    analyzer.println("WARN: Could not find instruction at address {} to determine branch target.".format(address_str))
            
            except Exception as e:
                analyzer.printerr("ERROR: Failed to process branch target for {}: {}".format(address_str, e))


            comparison_info = resolve_comparison_info(analyzer, address_str)

            if not comparison_info:
                analyzer.println("WARN: Could not resolve comparison for branch at {}. Skipping hook entry.".format(address_str))
                continue

            try:
                comp_addr_val = int(comparison_info["address_str"], 16)
                modified_comp_address_str = "0x{:x}".format(comp_addr_val - 0x100000)
            except ValueError:
                analyzer.printerr("WARN: Could not parse comparison address '{}' for hook config. Skipping.".format(comparison_info["address_str"]))
                continue

            try:
                branch_addr_val = int(address_str, 16)
                modified_branch_address_str = "0x{:x}".format(branch_addr_val - 0x100000)
            except ValueError:
                modified_branch_address_str = "N/A"
            
            cleaned_operands = [analyzer.cleanup_operand_repr(op) for op in comparison_info["operands"]]
            registers_with_info = [{"register": reg} for reg in cleaned_operands]

            set_id = usage.get("originating_imported_function_name", "unknown_set")

            entry = {
                "address": modified_comp_address_str,
                "instruction": comparison_info["instruction_str"],
                "registers": registers_with_info,
                "branch_target": branch_target_str,
                "original_branch_address": modified_branch_address_str,
                "original_branch_instruction": usage.get("instruction_mnemonic", "N/A").lower(),
                "pcode_compared_ops": usage.get("compared_ops_repr", []),
                "set_id": set_id
            }
            hook_entries.append(entry)

    if not hook_entries:
        analyzer.println("No tainted branch conditions found to generate a hook config.")
        return

    script_dir = os.path.dirname(os.path.realpath(__file__))
    results_dir = os.path.join(script_dir, "results")
    
    if not os.path.exists(results_dir):
        try:
            os.makedirs(results_dir)
        except OSError:
            pass

    program_name = analyzer.current_program.getName()
    output_filename = "{}_hook_config.json".format(program_name)
    output_file_path = os.path.join(results_dir, output_filename)

    try:
        with open(output_file_path, 'w') as f:
            json.dump(hook_entries, f, indent=4)
        analyzer.println("SUCCESS: Hook configuration saved to: {}".format(output_file_path))
    except Exception as e:
        analyzer.printerr("ERROR: Could not write hook config to file {}: {}".format(output_file_path, e))


def run_analysis_from_ghidra_ui():
    if not all((_current_program, _monitor, _println, _printerr, _askFile, _askString)):
        sys.stderr.write("Error: This script must be run within a full Ghidra environment.\n")
        return

    analyzer = None
    try:
        analyzer = TaintAnalyzer(
            current_program=_current_program,
            monitor=_monitor,
            println=_println,
            printerr=_printerr,
            askFile=_askFile
        )
        
        target_library_name = None
        function_name_substring_fallback = None
        try:
            script_args = getScriptArgs() 
            if script_args and len(script_args) > 0:
                target_library_name = script_args[0]
                if len(script_args) > 1:
                    function_name_substring_fallback = script_args[1]
            else:
                _printerr("ERROR: Missing arguments. Please provide at least the target library name.")
                _printerr("  - From Headless: ./run_headless_test.sh library_analyzer.py <binary> <library_name> [function_substring_fallback]")
                _printerr("  - From UI: Right-click script -> Run With Arguments... -> Enter <library_name> [function_substring_fallback]")
                return
        except NameError:
             _printerr("ERROR: Could not find getScriptArgs(). This script must be run within Ghidra.")
             return

        if not target_library_name:
            _println("Analysis cancelled. No library name provided.")
            return
        
        target_library_name = target_library_name.strip()
        _println("INFO: Target library set to '{}'".format(target_library_name))
        if function_name_substring_fallback:
            function_name_substring_fallback = function_name_substring_fallback.strip()
            _println("INFO: Fallback function name substring set to '{}'".format(function_name_substring_fallback))

        func_manager = _current_program.getFunctionManager()
        ref_manager = _current_program.getReferenceManager()
        ext_manager = _current_program.getExternalManager()
        
        _println("\n--- Searching for function names in library '{}' using ExternalManager... ---".format(target_library_name))
        target_function_names = set()
        locations_iterator = ext_manager.getExternalLocations(target_library_name)
        _println("locations_iterator: {}".format(locations_iterator))
        for loc in locations_iterator:
            _println("loc: {}".format(loc))
            symbol = loc.getSymbol()
            if symbol:
                target_function_names.add(symbol.getName())

        if not target_function_names:
            _println("INFO: ExternalManager found no function symbols for library '{}'.".format(target_library_name))
        else:
            _println("INFO: ExternalManager identified the following function names: {}".format(list(target_function_names)))

        _println("\n--- Searching for matching Function objects in the FunctionManager... ---")
        all_callable_targets = set()
        all_functions_iter = func_manager.getFunctions(True)
        for func in all_functions_iter:
            target_name_match = False
            if func.getName() in target_function_names:
                target_name_match = True
            
            thunked_func = func.getThunkedFunction(True)
            if not target_name_match and thunked_func and thunked_func.getName() in target_function_names:
                target_name_match = True

            if target_name_match:
                 _println("    [DEBUG] MATCH FOUND! Adding function '{}' at {} to targets.".format(func.getName(), func.getEntryPoint()))
                 all_callable_targets.add(func)

        _println("--- Finished searching for library functions. ---")

        origin_source_name = target_library_name
        if not all_callable_targets and function_name_substring_fallback:
            _println("\n--- Library search failed. Attempting fallback search using substring: '{}' ---".format(function_name_substring_fallback))
            origin_source_name = function_name_substring_fallback
            
            all_functions_iter_fallback = func_manager.getFunctions(True)
            for func in all_functions_iter_fallback:
                if function_name_substring_fallback in func.getName():
                     _println("    [DEBUG] FALLBACK MATCH FOUND! Adding function '{}' at {} to targets.".format(func.getName(), func.getEntryPoint()))
                     all_callable_targets.add(func)
            _println("--- Finished fallback search. ---")
        
        _println("--- Finished searching for functions. ---\n")

        if not all_callable_targets:
            _printerr("ERROR: No callable targets found. Primary search for library '{}' failed, and fallback search for substring '{}' also failed (or was not provided).".format(target_library_name, function_name_substring_fallback or "N/A"))
            return
        
        _println("INFO: Found {} functions/thunks to analyze from source '{}'.".format(len(all_callable_targets), origin_source_name))

        call_sites_by_function = defaultdict(list)
        for target in all_callable_targets:
            refs = ref_manager.getReferencesTo(target.getEntryPoint())
            for ref in refs:
                if ref.getReferenceType().isCall():
                    containing_func = func_manager.getFunctionContaining(ref.getFromAddress())
                    if containing_func and not containing_func.equals(target):
                        call_sites_by_function[containing_func].append(ref.getFromAddress())
        
        if not call_sites_by_function:
            _println("INFO: No call sites found for any functions in the target list.")
            return
            
        _println("INFO: Found {} unique functions containing call sites. Analyzing each...".format(len(call_sites_by_function)))

        for parent_func, call_site_addrs in call_sites_by_function.items():
            _println("\n--- Analyzing Function '{}' containing {} call site(s) ---".format(parent_func.getName(), len(call_site_addrs)))

            decompile_results = analyzer.decompiler.decompileFunction(parent_func, 60, analyzer.monitor)
            if not decompile_results or not decompile_results.getHighFunction():
                _printerr("ERROR: Failed to decompile parent function {}. Skipping.".format(parent_func.getName()))
                continue
            
            high_parent_func = decompile_results.getHighFunction()

            for call_site_addr in call_site_addrs:
                _println("\n  -- Analyzing Call Site at {} --".format(call_site_addr))
                target_call_op = None
                op_iter = high_parent_func.getPcodeOps(call_site_addr)
                while op_iter.hasNext():
                    pcode_op = op_iter.next()
                    if pcode_op.getMnemonic() in ["CALL", "CALLIND"]:
                        target_call_op = pcode_op
                        break
                
                if not target_call_op:
                    _printerr("ERROR: No CALL/CALLIND P-code op at {}. Skipping site.".format(call_site_addr))
                    continue

                called_function_obj = analyzer._get_called_function_from_pcode_op(target_call_op)
                api_full_name = called_function_obj.getName() if called_function_obj else origin_source_name

                if target_call_op.getNumInputs() < 2:
                    _println("INFO: Call at {} has no parameters. Skipping taint from last parameter.".format(call_site_addr))
                    continue

                last_param_vn = target_call_op.getInput(target_call_op.getNumInputs() - 1)
                if not last_param_vn:
                    _println("WARN: Could not get last parameter varnode at {}. Skipping site.".format(call_site_addr))
                    continue
                
                last_param_hv = last_param_vn.getHigh()
                if not last_param_hv:
                    _println("WARN: Last parameter at {} has no HighVariable. Cannot taint. Skipping site.".format(call_site_addr))
                    continue
                
                initial_taint_set_for_this_call = {last_param_hv}
                _println("INFO: Tainting last parameter from call at {}: {}".format(call_site_addr, analyzer._get_varnode_representation(last_param_hv, high_parent_func)))

                analyzer._trace_taint_in_function(
                    high_func_to_analyze=high_parent_func,
                    initial_tainted_hvs=initial_taint_set_for_this_call,
                    pcode_op_start_taint=target_call_op,
                    originating_imported_func_name_for_log=api_full_name,
                    current_depth=0,
                    initial_tainted_stack_offsets=set(),
                    tainted_memory_regions=set()
                )

        _println("\n--- All Functions Analyzed. Finalizing Report. ---")
        analyzer._print_results()
        generate_hook_config(analyzer)

    except Exception as e:
        import traceback
        _effective_printerr = _printerr if _printerr else lambda msg: sys.stderr.write(str(msg) + "\n")
        _effective_printerr("An unhandled error occurred during LibraryAnalyzer execution:")
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
    try:
        from ghidra.app.script import GhidraScript
        _current_program = currentProgram
        _current_address = currentAddress
        _monitor = monitor
        _println = println
        _printerr = printerr
        _askFile = askFile
        _askString = askString
    except ImportError:
        import sys
        _current_program = None
        _current_address = None
        _monitor = None
        _println = lambda msg: sys.stdout.write(str(msg) + "\n")
        _printerr = lambda msg: sys.stderr.write(str(msg) + "\n")
        _askFile = None
        _askString = None
        sys.path.append(os.path.dirname(os.path.realpath(__file__)))
    
    if 'currentProgram' in globals() and globals().get('currentProgram') is not None:
        run_analysis_from_ghidra_ui()
    else:
        print("This script is designed to be run from within Ghidra's Script Manager.")
    
    _final_println = globals().get('println', lambda x: None)
    _final_println("Library Taint Analyzer finished.") 