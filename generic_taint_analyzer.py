# analyze_mnn_taint_modular.py
# Modularized version of the taint analysis script.
# Analyzes taint propagation starting from the return value of calls to functions
# matching a specific keyword (e.g., 'getSessionOutput').

# Import necessary Ghidra modules
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

class TaintAnalyzer:
    """
    Encapsulates the entire taint analysis process.
    """
    # -------------------
    # Class Configuration
    # -------------------
    MAX_RECURSION_DEPTH = 5
    UNRESOLVED_CALL_EXPLORE_BUDGET = 3

    def __init__(self, current_program, monitor, println, printerr, askFile, rule_handlers=None):
        """
        Initializes the analyzer with necessary Ghidra services and state.
        :param rule_handlers: A list of functions to handle special taint propagation rules.
        """
        # Ghidra services
        self.current_program = current_program
        self.monitor = monitor
        self.println = println
        self.printerr = printerr
        self.askFile = askFile
        self.func_manager = current_program.getFunctionManager()
        self.ref_manager = current_program.getReferenceManager()
        self.decompiler = DecompInterface()
        options = DecompileOptions()
        self.decompiler.setOptions(options)
        self.decompiler.openProgram(self.current_program)

        # Analysis state
        self.all_tainted_usages = []
        self.visited_function_states = set()
        self.rule_handlers = rule_handlers if rule_handlers else []
        
    def __del__(self):
        """
        Dispose of the decompiler when the object is destroyed.
        """
        if self.decompiler:
            self.decompiler.dispose()
            self.println("DEBUG: Decompiler disposed.")

    # -------------------
    # Helper/Utility Methods (formerly global functions)
    # -------------------
    def _get_varnode_representation(self, varnode_obj, high_function_context):
        if varnode_obj is None: return "None"
        if high_function_context:
            actual_high_var_target = varnode_obj
            if not isinstance(varnode_obj, HighVariable):
                actual_high_var_target = varnode_obj.getHigh()
            if actual_high_var_target:
                display_name = actual_high_var_target.getName()
                storage_info_str = None
                symbol = actual_high_var_target.getSymbol()
                if symbol:
                    if symbol.getName() and symbol.getName() != "UnnamedSymbol":
                        if not display_name or ("Unnamed" in display_name and "Unnamed" not in symbol.getName()):
                            display_name = symbol.getName()
                    elif not display_name:
                        display_name = symbol.getName()
                    try:
                        vs = symbol.getStorage()
                        if vs and not vs.isInvalidStorage():
                            storage_info_str = vs.toString()
                    except AttributeError: pass
                if storage_info_str is None:
                    rep_vn = actual_high_var_target.getRepresentative()
                    if rep_vn:
                        if rep_vn.isRegister():
                            reg = self.current_program.getLanguage().getRegister(rep_vn.getAddress(), rep_vn.getSize())
                            storage_info_str = reg.getName() if reg else "Register"
                        elif rep_vn.getAddress() is not None and rep_vn.getAddress().isStackAddress():
                            storage_info_str = "Stack[{:#x}]".format(actual_high_var_target.getStackOffset()) if hasattr(actual_high_var_target, 'getStackOffset') else "StackDirect[{}]".format(rep_vn.getAddress().toString(True))
                        elif rep_vn.isUnique():
                            storage_info_str = "UniquePcode[0x{:x}]".format(rep_vn.getOffset())
                        elif rep_vn.isConstant():
                            storage_info_str = "Constant"
                        elif rep_vn.getAddress() is not None and rep_vn.getAddress().isMemoryAddress() and not rep_vn.getAddress().isStackAddress():
                             storage_info_str = "GlobalMem[{}]".format(rep_vn.getAddress().toString(True))
                    if storage_info_str is None and isinstance(actual_high_var_target, ghidra.program.model.pcode.HighOther):
                         storage_info_str = "HighOther"
                if display_name is None : display_name = "UnnamedHighVar"
                if storage_info_str:
                    return "{}({})".format(display_name, storage_info_str)
                else:
                    return "{} (HighVar Repr)".format(display_name)
        if varnode_obj.isRegister():
            reg = self.current_program.getLanguage().getRegister(varnode_obj.getAddress(), varnode_obj.getSize())
            return reg.getName() if reg else "reg_vn:{}".format(varnode_obj.getAddress())
        if varnode_obj.isConstant():
            return "const_vn:0x{:x}".format(varnode_obj.getOffset())
        if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isStackAddress():
            return "stack_vn_direct:{}".format(varnode_obj.getAddress().toString(True))
        if varnode_obj.isUnique():
            def_op = varnode_obj.getDef()
            if def_op:
                return "unique_vn:{}(def:{}) (size {})".format(varnode_obj.getOffset(), def_op.getMnemonic(), varnode_obj.getSize())
            return "unique_vn:{} (size {})".format(varnode_obj.getOffset(), varnode_obj.getSize())
        if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isMemoryAddress():
            return "mem_vn:{}".format(varnode_obj.getAddress().toString(True))
        return varnode_obj.toString()

    def _log_unresolved_call_with_tainted_args(self, pcode_op, current_high_func, tainted_hvs_from_caller,
                                             current_func_name, current_func_entry_addr_obj, op_addr_obj,
                                             originating_imported_func_name_for_log, context_msg=""):
        target_addr_vn = pcode_op.getInput(0)
        for arg_idx in range(1, pcode_op.getNumInputs()):
            arg_vn = pcode_op.getInput(arg_idx)
            arg_hv = arg_vn.getHigh() if arg_vn else None
            if arg_hv and arg_hv in tainted_hvs_from_caller:
                details_str = "Tainted argument #{} ({}) passed to unresolved call (target: {}). {}".format(
                    arg_idx - 1,
                    self._get_varnode_representation(arg_vn, current_high_func),
                    self._get_varnode_representation(target_addr_vn, current_high_func),
                    context_msg
                )
                self.all_tainted_usages.append({
                    "originating_imported_function_name": originating_imported_func_name_for_log,
                    "function_name": current_func_name,
                    "function_entry": current_func_entry_addr_obj.toString(),
                    "address": op_addr_obj.toString(),
                    "pcode_op_str": str(pcode_op),
                    "usage_type": "TAINTED_ARG_TO_UNRESOLVED_CALL",
                    "tainted_component_repr": self._get_varnode_representation(arg_vn, current_high_func),
                    "details": details_str.strip()
                })
                self.println("WARN: [{} @ {}] {}. Cannot recurse or explore further.".format(current_func_name, op_addr_obj.toString(), details_str.strip()))
                break

    def _get_called_function_from_pcode_op(self, pcode_op):
        """
        Helper to resolve the called function from a CALL or CALLIND PcodeOp.
        """
        called_function_obj = None
        op_address = pcode_op.getSeqnum().getTarget()
        target_func_addr_vn = pcode_op.getInput(0)
        
        if pcode_op.getMnemonic() == "CALL" and target_func_addr_vn.isConstant():
            try:
                called_func_address = self.current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                if called_func_address:
                    called_function_obj = self.func_manager.getFunctionAt(called_func_address)
            except Exception:
                pass
        
        # Fallback or for CALLIND
        if called_function_obj is None:
            # For CALLIND, the target is in a register, so we check references from the instruction
            ref_iter = self.ref_manager.getReferencesFrom(op_address, 0)
            for ref in ref_iter:
                if ref.getReferenceType().isCall():
                    func_from_ref = self.func_manager.getFunctionAt(ref.getToAddress())
                    if func_from_ref:
                        called_function_obj = func_from_ref
                        break
        return called_function_obj

    # -------------------
    # Core Taint Tracing Logic (as a method)
    # -------------------
    def _trace_taint_in_function(self, high_func_to_analyze, initial_tainted_hvs, pcode_op_start_taint,
                                originating_imported_func_name_for_log, current_depth=0,
                                sub_recursion_budget=None, current_sub_depth=0):
        if current_depth > self.MAX_RECURSION_DEPTH:
            self.println("DEBUG: Max recursion depth ({}) reached.".format(self.MAX_RECURSION_DEPTH))
            return

        if sub_recursion_budget is not None and current_sub_depth >= sub_recursion_budget:
            self.println("DEBUG: Sub-recursion budget ({}) reached. Stopping this sub-path for {}.".format(
                sub_recursion_budget, high_func_to_analyze.getFunction().getName()
            ))
            return

        func_entry_addr = high_func_to_analyze.getFunction().getEntryPoint()
        func_name = high_func_to_analyze.getFunction().getName()

        initial_tainted_hvs_repr_list = sorted([self._get_varnode_representation(hv, high_func_to_analyze) for hv in initial_tainted_hvs])
        initial_tainted_hvs_repr_tuple = tuple(initial_tainted_hvs_repr_list)
        current_state_key = (func_entry_addr.toString(), initial_tainted_hvs_repr_tuple, originating_imported_func_name_for_log)

        if current_state_key in self.visited_function_states:
            self.println("DEBUG: Already analyzed function {} with initial taints {} (origin: {}). Skipping.".format(func_name, initial_tainted_hvs_repr_tuple, originating_imported_func_name_for_log))
            return
        self.visited_function_states.add(current_state_key)

        self.println("\\n>>> Analyzing function: {} (Depth: {}) at {} (Originating from: {}) with initial taints: {}".format(
            func_name, current_depth, func_entry_addr, originating_imported_func_name_for_log,
            ", ".join([self._get_varnode_representation(hv, high_func_to_analyze) for hv in initial_tainted_hvs])
        ))

        current_func_input_param_hvs = set()
        try:
            local_symbol_map = high_func_to_analyze.getLocalSymbolMap()
            if local_symbol_map:
                symbol_iterator = local_symbol_map.getSymbols()
                while symbol_iterator.hasNext():
                    sym = symbol_iterator.next()
                    if sym and sym.isParameter():
                        hv = sym.getHighVariable()
                        if hv: current_func_input_param_hvs.add(hv)
        except Exception as e:
            self.printerr("Error getting input parameters for {}: {}".format(func_name, e))

        tainted_high_vars_in_current_func = set(initial_tainted_hvs)
        tainted_high_var_representations_in_current_func = set()
        for hv_init in initial_tainted_hvs:
            tainted_high_var_representations_in_current_func.add(
                self._get_varnode_representation(hv_init, high_func_to_analyze)
            )

        # Convert iterator to list to allow indexed access for forward scanning
        all_pcode_ops_in_func = []
        op_iter_for_analysis = high_func_to_analyze.getPcodeOps()
        while op_iter_for_analysis.hasNext():
            all_pcode_ops_in_func.append(op_iter_for_analysis.next())

        start_idx = 0
        if pcode_op_start_taint:
            # If a start op is specified, find its index
            for i, op in enumerate(all_pcode_ops_in_func):
                if op.getSeqnum().equals(pcode_op_start_taint.getSeqnum()):
                    start_idx = i
                    self.println("\\nDEBUG: Reached specified start PcodeOp {} at {} in {}, subsequent ops will be processed.".format(
                        op, op.getSeqnum().getTarget().toString(), func_name
                    ))
                    break
        else:
             self.println("DEBUG: Starting taint analysis from the beginning of function {}.".format(func_name))


        for op_idx in range(start_idx, len(all_pcode_ops_in_func)):
            current_pcode_op = all_pcode_ops_in_func[op_idx]
            current_op_address = current_pcode_op.getSeqnum().getTarget()
            current_op_address_str = current_op_address.toString()
            
            output_vn = current_pcode_op.getOutput()
            output_hv = output_vn.getHigh() if output_vn else None
            mnemonic = current_pcode_op.getMnemonic()

            if mnemonic == "CBRANCH":
                condition_vn = current_pcode_op.getInput(1)
                condition_hv = condition_vn.getHigh() if condition_vn else None
                condition_is_tainted = False; condition_hv_repr = "N/A"
                if condition_hv:
                    condition_hv_repr = self._get_varnode_representation(condition_hv, high_func_to_analyze)
                    if (condition_hv in tainted_high_vars_in_current_func or condition_hv_repr in tainted_high_var_representations_in_current_func): condition_is_tainted = True
                if condition_is_tainted:
                    details_cbranch = "Tainted condition for branch."; compared_ops_repr = ["N/A", "N/A"]
                    def_op_cond = condition_vn.getDef()
                    if def_op_cond and def_op_cond.getNumInputs() >= 2 and def_op_cond.getMnemonic() in ["INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_AND", "BOOL_OR"]:
                        op1_vn_cond = def_op_cond.getInput(0); op2_vn_cond = def_op_cond.getInput(1)
                        compared_ops_repr = [self._get_varnode_representation(op1_vn_cond, high_func_to_analyze), self._get_varnode_representation(op2_vn_cond, high_func_to_analyze)]
                    skip_this_cbranch_report_due_to_assembly = False
                    instruction_at_op = self.current_program.getListing().getInstructionAt(current_op_address)
                    if instruction_at_op and instruction_at_op.getMnemonicString().lower() in ["cbz", "cbnz"]: skip_this_cbranch_report_due_to_assembly = True
                    if not skip_this_cbranch_report_due_to_assembly:
                        self.all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "BRANCH_CONDITION_TAINTED", "tainted_component_repr": condition_hv_repr, 
                            "compared_operands": compared_ops_repr, "details": details_cbranch
                        })
                        self.println("INFO: [{} @ {}] Taint reached CBRANCH. Operands: {}.".format(func_name, current_op_address_str, compared_ops_repr))

            if mnemonic == "STORE":
                stored_value_vn = current_pcode_op.getInput(2)
                stored_value_hv = stored_value_vn.getHigh() if stored_value_vn else None
                if stored_value_hv and stored_value_hv in tainted_high_vars_in_current_func:
                    dest_addr_vn = current_pcode_op.getInput(1)
                    dest_hv = dest_addr_vn.getHigh() if dest_addr_vn else None
                    usage_entry_store = {
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                        "tainted_component_repr": self._get_varnode_representation(stored_value_vn, high_func_to_analyze),
                        "destination_repr": self._get_varnode_representation(dest_addr_vn, high_func_to_analyze)
                    }
                    if dest_hv and dest_hv in current_func_input_param_hvs and dest_hv not in initial_tainted_hvs:
                        details_store_term = "Tainted value stored into input parameter {} of {}. Path terminated.".format(self._get_varnode_representation(dest_hv, high_func_to_analyze), func_name)
                        usage_entry_store["usage_type"] = "TAINT_REACHED_INPUT_PARAMETER_TERMINATION"
                        usage_entry_store["details"] = details_store_term
                        self.all_tainted_usages.append(usage_entry_store)
                        self.println("INFO: [{} @ {}] {}.".format(func_name, current_op_address_str, details_store_term))
                        return 
                    else:
                        usage_entry_store["usage_type"] = "STORE_TAINTED_VALUE"
                        usage_entry_store["details"] = "Tainted value stored."
                        self.all_tainted_usages.append(usage_entry_store)

            elif mnemonic == "RETURN":
                if current_pcode_op.getNumInputs() > 1:
                    returned_value_vn = current_pcode_op.getInput(1)
                    returned_value_hv = returned_value_vn.getHigh() if returned_value_vn else None
                    if returned_value_hv and returned_value_hv in tainted_high_vars_in_current_func:
                        self.all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "RETURN_TAINTED_VALUE", 
                            "tainted_component_repr": self._get_varnode_representation(returned_value_vn, high_func_to_analyze)
                        })
            
            if mnemonic in ["CALL", "CALLIND"]:
                called_function_obj = self._get_called_function_from_pcode_op(current_pcode_op)
                
                if called_function_obj:
                    # --- Custom Rule Handling ---
                    was_handled_by_rule = False
                    for handler in self.rule_handlers:
                        # A handler should return True if it processed the op and no further generic processing is needed.
                        if handler(self, op_idx, all_pcode_ops_in_func, high_func_to_analyze, tainted_high_vars_in_current_func, tainted_high_var_representations_in_current_func, originating_imported_func_name_for_log):
                            was_handled_by_rule = True
                            break
                    
                    if was_handled_by_rule:
                        continue
                    # --- END Custom Rule Handling ---

                    # First, check if any arguments are tainted.
                    is_any_arg_tainted = False
                    tainted_args_for_log = []
                    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()):
                        caller_arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                        caller_arg_hv = caller_arg_vn.getHigh()
                        if caller_arg_hv and caller_arg_hv in tainted_high_vars_in_current_func:
                            is_any_arg_tainted = True
                            tainted_args_for_log.append(self._get_varnode_representation(caller_arg_hv, high_func_to_analyze))

                    # If the call is to a thunk function and has tainted arguments, apply special taint propagation rules.
                    if called_function_obj.isExternal() and is_any_arg_tainted:
                        self.println("INFO: [THUNK_CALL] Tainted arg(s) {} passed to thunk function '{}'. Not recursing, applying special taint propagation.".format(
                            ", ".join(tainted_args_for_log),
                            called_function_obj.getName()
                        ))
                        
                        # Rule 1: Taint the return value of the thunk call.
                        call_output_vn = current_pcode_op.getOutput()
                        if call_output_vn:
                            call_output_hv = call_output_vn.getHigh()
                            if call_output_hv and call_output_hv not in tainted_high_vars_in_current_func:
                                tainted_high_vars_in_current_func.add(call_output_hv)
                                output_hv_repr = self._get_varnode_representation(call_output_hv, high_func_to_analyze)
                                tainted_high_var_representations_in_current_func.add(output_hv_repr)
                                self.println("DEBUG: [THUNK_CALL] Tainting return value: {}".format(output_hv_repr))
                                self.all_tainted_usages.append({
                                    "originating_imported_function_name": originating_imported_func_name_for_log,
                                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                    "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                                    "usage_type": "TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN",
                                    "tainted_component_repr": output_hv_repr,
                                    "details": "Return value of thunk call {} tainted due to tainted input(s).".format(called_function_obj.getName())
                                })
                        
                        # Rule 2: Taint any input parameters that are pointers.
                        for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()):
                            arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                            arg_hv = arg_vn.getHigh()
                            if arg_hv and isinstance(arg_hv.getDataType(), Pointer):
                                if arg_hv not in tainted_high_vars_in_current_func:
                                    tainted_high_vars_in_current_func.add(arg_hv)
                                    arg_hv_repr = self._get_varnode_representation(arg_hv, high_func_to_analyze)
                                    tainted_high_var_representations_in_current_func.add(arg_hv_repr)
                                    self.println("DEBUG: [THUNK_CALL] Tainting pointer argument: {}".format(arg_hv_repr))
                                    self.all_tainted_usages.append({
                                        "originating_imported_function_name": originating_imported_func_name_for_log,
                                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                                        "usage_type": "TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG",
                                        "tainted_component_repr": arg_hv_repr,
                                        "details": "Input pointer argument to thunk call {} is now tainted.".format(called_function_obj.getName())
                                    })
                        
                        continue # Skip the normal recursion logic and move to the next p-code op.
                
                high_called_func = None
                if called_function_obj: # Ensure we have a function object before trying to decompile
                    try:
                        decompile_res_callee = self.decompiler.decompileFunction(called_function_obj, 60, self.monitor)
                        if decompile_res_callee and decompile_res_callee.getHighFunction(): high_called_func = decompile_res_callee.getHighFunction()
                    except Exception as de: self.printerr("ERROR: Decompile callee {}: {}".format(called_function_obj.getName(), de))
                
                if high_called_func:
                    callee_func_proto = high_called_func.getFunctionPrototype()
                    num_formal_params = callee_func_proto.getNumParams() if callee_func_proto else 0
                    newly_tainted_callee_hvs = set()
                    tainted_arg_details_for_no_map = []
                    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()): 
                        caller_arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                        caller_arg_hv = caller_arg_vn.getHigh()
                        if caller_arg_hv and caller_arg_hv in tainted_high_vars_in_current_func:
                            conceptual_arg_idx = pcode_arg_idx - 1
                            tainted_arg_details_for_no_map.append("PCodeArg#{}:{}".format(conceptual_arg_idx, self._get_varnode_representation(caller_arg_vn, high_func_to_analyze)))
                            if callee_func_proto and conceptual_arg_idx < num_formal_params:
                                callee_param_symbol = callee_func_proto.getParam(conceptual_arg_idx)
                                hv_to_taint = callee_param_symbol.getHighVariable() if callee_param_symbol else None
                                if hv_to_taint: newly_tainted_callee_hvs.add(hv_to_taint)
                                else: self.println("WARN: Tainted arg for {}, but no HighVar for callee param #{}.".format(called_function_obj.getName(),conceptual_arg_idx ))
                            else: 
                                pass # Will be logged below if newly_tainted_callee_hvs is empty but tainted_arg_details_for_no_map is not
                    if newly_tainted_callee_hvs:
                        self.all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_RECURSION",
                            "details": "Recursive call to {} ({}) with taints: {}.".format(called_function_obj.getName(), mnemonic, ", ".join([self._get_varnode_representation(h, high_called_func) for h in newly_tainted_callee_hvs]))
                        })
                        self._trace_taint_in_function(high_called_func, newly_tainted_callee_hvs, None, originating_imported_func_name_for_log, current_depth + 1, sub_recursion_budget=sub_recursion_budget, current_sub_depth=current_sub_depth +1 if sub_recursion_budget is not None else 0)
                    elif tainted_arg_details_for_no_map: # Tainted args exist but couldn't be mapped
                        self.all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
                            "details": "Tainted PCode args ({}) to {} ({}) cannot map to HighProto (count {}).".format(", ".join(tainted_arg_details_for_no_map), called_function_obj.getName(), mnemonic, num_formal_params)
                        })
                else: # Unresolved call
                    potential_target_addr_to_explore = None; exploration_context_msg = ""
                    if target_func_addr_vn.isConstant():
                        try:
                            addr = self.current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                            if addr: potential_target_addr_to_explore = addr; exploration_context_msg = "PCode target const addr {}".format(addr)
                        except: pass
                    elif target_func_addr_vn.isAddress() and target_func_addr_vn.getAddress().isMemoryAddress() and not target_func_addr_vn.getAddress().isStackAddress():
                        pointer_loc_addr = target_func_addr_vn.getAddress()
                        try:
                            mem = self.current_program.getMemory()
                            ptr_val = mem.getLong(pointer_loc_addr) if self.current_program.getDefaultPointerSize() == 8 else (mem.getInt(pointer_loc_addr) & 0xFFFFFFFF)
                            addr = self.current_program.getAddressFactory().getAddress(hex(ptr_val))
                            if addr: potential_target_addr_to_explore = addr; exploration_context_msg = "PCode target RAM {}, read ptr {} -> target {}".format(pointer_loc_addr, hex(ptr_val), addr)
                        except: pass
                    if potential_target_addr_to_explore and (current_depth < self.MAX_RECURSION_DEPTH):
                        attempted_func_obj = self.func_manager.getFunctionAt(potential_target_addr_to_explore)
                        if attempted_func_obj:
                            high_attempted_func = None
                            try:
                                decompile_res_attempt = self.decompiler.decompileFunction(attempted_func_obj, 60, self.monitor)
                                if decompile_res_attempt and decompile_res_attempt.getHighFunction(): high_attempted_func = decompile_res_attempt.getHighFunction()
                            except: pass
                            if high_attempted_func:
                                attempted_callee_proto = high_attempted_func.getFunctionPrototype()
                                num_formal_attempted = attempted_callee_proto.getNumParams() if attempted_callee_proto else 0
                                newly_tainted_attempt = set(); any_tainted_arg_for_attempt = False; tainted_arg_details_attempt_no_map = []
                                for arg_idx_pcode_attempt in range(1, current_pcode_op.getNumInputs()):
                                    arg_vn_attempt = current_pcode_op.getInput(arg_idx_pcode_attempt)
                                    arg_hv_attempt = arg_vn_attempt.getHigh()
                                    if arg_hv_attempt and arg_hv_attempt in tainted_high_vars_in_current_func:
                                        any_tainted_arg_for_attempt = True
                                        tainted_arg_details_attempt_no_map.append("PCodeArg#{}:{}".format(arg_idx_pcode_attempt-1, self._get_varnode_representation(arg_vn_attempt, high_func_to_analyze)))
                                        if attempted_callee_proto and (arg_idx_pcode_attempt -1) < num_formal_attempted:
                                            param_sym_att = attempted_callee_proto.getParam(arg_idx_pcode_attempt -1)
                                            hv_to_taint_att = param_sym_att.getHighVariable() if param_sym_att else None
                                            if hv_to_taint_att: newly_tainted_attempt.add(hv_to_taint_att)
                                if newly_tainted_attempt:
                                    self.all_tainted_usages.append({"originating_imported_function_name": originating_imported_func_name_for_log, "function_name": func_name, "function_entry": func_entry_addr.toString(), "address": current_op_address_str, "pcode_op_str": str(current_pcode_op), "usage_type": "EXPLORING_INITIALLY_UNRESOLVED_CALL", "details": "Exploring {} to {} ({}) with taints. Budget: {}.".format(mnemonic, attempted_func_obj.getName(), exploration_context_msg, self.UNRESOLVED_CALL_EXPLORE_BUDGET)})
                                    self._trace_taint_in_function(high_attempted_func, newly_tainted_attempt, None, originating_imported_func_name_for_log, current_depth + 1, sub_recursion_budget=self.UNRESOLVED_CALL_EXPLORE_BUDGET, current_sub_depth=0)
                                elif any_tainted_arg_for_attempt:
                                     self.all_tainted_usages.append({"originating_imported_function_name": originating_imported_func_name_for_log, "function_name": func_name, "function_entry": func_entry_addr.toString(), "address": current_op_address_str, "pcode_op_str": str(current_pcode_op), "usage_type": "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP", "details": "Tainted args ({}) to {} (resolved to {}), but no HighProto map. {}".format(", ".join(tainted_arg_details_attempt_no_map), mnemonic, attempted_func_obj.getName(), exploration_context_msg)})
                            else: self._log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, originating_imported_func_name_for_log, "(decomp failed for explored {})".format(exploration_context_msg))
                        else: self._log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, originating_imported_func_name_for_log, "(no func obj at explored {})".format(exploration_context_msg))
                    else: self._log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, originating_imported_func_name_for_log, "(cannot explore target)")

            if output_hv and output_hv not in tainted_high_vars_in_current_func:
                is_newly_tainted = False; source_of_taint_repr = "N/A"
                unary_ops = ["COPY", "CAST", "INT_NEGATE", "INT_2COMP", "POPCOUNT", "INT_ZEXT", "INT_SEXT", "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND", "INT2FLOAT", "FLOAT2INT", "BOOL_NEGATE"]
                multi_ops = ["INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "MULTIEQUAL", "PIECE", "SUBPIECE", "PTRADD", "PTRSUB"]
                load_op = "LOAD"; inputs_to_check = []
                if mnemonic == load_op and current_pcode_op.getNumInputs() > 1: inputs_to_check.append(current_pcode_op.getInput(1))
                elif mnemonic in unary_ops and current_pcode_op.getNumInputs() > 0: inputs_to_check.append(current_pcode_op.getInput(0))
                elif mnemonic in multi_ops:
                    if mnemonic == "SUBPIECE" and current_pcode_op.getNumInputs() > 0: inputs_to_check.append(current_pcode_op.getInput(0))
                    else: 
                        for i in range(current_pcode_op.getNumInputs()): inputs_to_check.append(current_pcode_op.getInput(i))
                for input_vn in inputs_to_check:
                    if input_vn:
                        input_hv = input_vn.getHigh()
                        if input_hv:
                            input_hv_repr = self._get_varnode_representation(input_hv, high_func_to_analyze)
                            if (mnemonic == load_op and (input_hv_repr in tainted_high_var_representations_in_current_func or input_hv in tainted_high_vars_in_current_func)) or (mnemonic != load_op and input_hv in tainted_high_vars_in_current_func):
                                is_newly_tainted = True; source_of_taint_repr = input_hv_repr; break
                if is_newly_tainted:
                    should_add_taint_prop = True; is_strlen_call_output = False
                    if mnemonic in ["CALL", "CALLIND"] and output_vn and output_vn.getHigh() == output_hv:
                        called_func_strlen_check = None; target_vn_strlen = current_pcode_op.getInput(0)
                        if mnemonic == "CALL" and target_vn_strlen.isConstant():
                            try:
                                addr_strlen = self.current_program.getAddressFactory().getAddress(hex(target_vn_strlen.getOffset()))
                                if addr_strlen: called_func_strlen_check = self.func_manager.getFunctionAt(addr_strlen)
                            except: pass
                        else:
                            ref_iter_strlen = self.ref_manager.getReferencesFrom(current_op_address, 0)
                            for ref_strlen in ref_iter_strlen:
                                if ref_strlen.getReferenceType().isCall():
                                    func_from_ref_strlen = self.func_manager.getFunctionAt(ref_strlen.getToAddress())
                                    if func_from_ref_strlen: called_func_strlen_check = func_from_ref_strlen; break
                        if called_func_strlen_check and called_func_strlen_check.getName() == "strlen": is_strlen_call_output = True
                    if is_strlen_call_output:
                        self.println("DEBUG: [STRLEN SUPPRESSION] Output of strlen CALL {} will NOT be tainted.".format(self._get_varnode_representation(output_hv, high_func_to_analyze)))
                        should_add_taint_prop = False
                    if should_add_taint_prop:
                        tainted_high_vars_in_current_func.add(output_hv)
                        output_hv_repr_set = self._get_varnode_representation(output_hv, high_func_to_analyze)
                        tainted_high_var_representations_in_current_func.add(output_hv_repr_set)
                        self.println("DEBUG: [{} @ {}] Taint propagated from {} to {} via {}.".format(func_name, current_op_address_str, source_of_taint_repr, output_hv_repr_set, mnemonic))

            if output_hv and output_hv in tainted_high_vars_in_current_func:
                if output_hv in current_func_input_param_hvs and output_hv not in initial_tainted_hvs:
                    details_param_term = "Taint propagated to input parameter {} of {}. Path terminated.".format(self._get_varnode_representation(output_hv, high_func_to_analyze), func_name)
                    self.all_tainted_usages.append({
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                        "usage_type": "TAINT_REACHED_INPUT_PARAMETER_TERMINATION",
                        "tainted_component_repr": self._get_varnode_representation(output_hv, high_func_to_analyze),
                        "details": details_param_term
                    })
                    self.println("INFO: [{} @ {}] {}.".format(func_name, current_op_address_str, details_param_term))
                    return 
        self.println("<<< Finished analyzing function: {}.".format(func_name))

    # -------------------
    # Output/Reporting Methods
    # -------------------
    def _print_results(self):
        if not self.all_tainted_usages:
            self.println("No tainted usages to print.")
            return

        self.println("\\n--- All Detected Tainted Value Usages (Interprocedural) ---")
        included_usage_types = [
            "BRANCH_CONDITION_TAINTED",
            "TAINTED_ARG_TO_CALL_RECURSION",
            "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
            "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP",
            "TAINTED_ARG_TO_UNRESOLVED_CALL",
            "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
            "RETURN_TAINTED_VALUE",
            "TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN",
            "TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG",
            "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN"
        ]
        cpu_flag_core_names = [
            "tmpcy", "ng", "zf", "cf", "of", "sf", "pf", 
            "tmpnz", "tmpov", "tmpca", "af", 
            "cc_n", "cc_z", "cc_c", "cc_v"
        ]
        filtered_results_to_print = []
        for res in self.all_tainted_usages:
            include_this_result = False
            if res["usage_type"] in included_usage_types:
                include_this_result = True
                if res["usage_type"] == "BRANCH_CONDITION_TAINTED":
                    is_cpu_flag_component = False
                    tainted_comp_repr = res.get("tainted_component_repr", "")
                    lc_tainted_comp_repr = tainted_comp_repr.lower()
                    for flag_name in cpu_flag_core_names:
                        if "({}".format(flag_name) in lc_tainted_comp_repr and lc_tainted_comp_repr.endswith(")"):
                            last_paren_open_idx = lc_tainted_comp_repr.rfind('(')
                            if last_paren_open_idx != -1 and lc_tainted_comp_repr[-1] == ')':
                                content_in_paren = lc_tainted_comp_repr[last_paren_open_idx+1:-1]
                                if content_in_paren == flag_name:
                                    is_cpu_flag_component = True; break
                        if lc_tainted_comp_repr == flag_name:
                            is_cpu_flag_component = True; break
                    if is_cpu_flag_component:
                        include_this_result = False
            if include_this_result:
                filtered_results_to_print.append(res)

        if not filtered_results_to_print:
            self.println("No usages matching the current filter were found.")
            return

        usage_counter = 0
        for res in filtered_results_to_print:
            usage_counter += 1
            self.println("Usage #{}:".format(usage_counter))
            if "originating_imported_function_name" in res:
                 self.println("  Originating Lib Call: {}".format(res["originating_imported_function_name"]))
            if "function_name" in res:
                self.println("  Found In Function:   {} at {}".format(res["function_name"], res.get("function_entry", "N/A")))
            self.println("  Instruction Address: {}".format(res["address"]))
            self.println("    PCode Op:            {}".format(res["pcode_op_str"]))
            self.println("    Usage Type:          {}".format(res["usage_type"]))
            if "tainted_component_repr" in res:
                 self.println("    Tainted Component:   {}".format(res["tainted_component_repr"]))
            if "destination_repr" in res:
                 self.println("    Destination Address: {}".format(res["destination_repr"]))
            if "compared_operands" in res:
                 self.println("    Compared Operands:   {} vs {}".format(res["compared_operands"][0], res["compared_operands"][1]))
            if "details" in res and res["details"] is not None:
                 self.println("    Details:             {}".format(res["details"]))
            self.println("-" * 40)

    def _save_results_to_json(self):
        if not self.all_tainted_usages:
            self.println("No tainted usages to save to JSON.")
            return

        output_file_path = None
        # --- Headless Mode Support ---
        # Check for an environment variable to specify the output path, which is ideal for headless execution.
        headless_output_path = os.getenv('TAINT_ANALYSIS_JSON_OUTPUT')
        
        if headless_output_path:
            output_file_path = headless_output_path
            self.println("INFO: TAINT_ANALYSIS_JSON_OUTPUT env var found. Saving results to: {}".format(output_file_path))
        elif self.askFile is None:
            self.printerr("WARN: Headless mode detected (askFile not available) and TAINT_ANALYSIS_JSON_OUTPUT env var not set.")
            output_file_path = "taint_analysis_results.json"
            self.println("WARN: Will attempt to save JSON to default relative path: {}".format(output_file_path))
        else:
            # --- GUI Mode ---
            try:
                output_file_obj = self.askFile("Save Taint Analysis JSON Output", "Save")
                if not output_file_obj:
                    self.println("JSON output cancelled by user.")
                    return
                output_file_path = output_file_obj.getAbsolutePath()
            except Exception as e_askfile:
                self.printerr("Error using askFile function: {}. Falling back to default path.".format(e_askfile))
                output_file_path = "taint_analysis_results.json"
                self.println("Will attempt to save JSON to default path: {}".format(output_file_path))
        
        if not output_file_path:
            self.printerr("Error: Output file path for JSON was not determined. Cannot save results.")
            return

        included_usage_types_for_json = [
            "BRANCH_CONDITION_TAINTED", "TAINTED_ARG_TO_CALL_RECURSION",
            "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS", "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP",
            "TAINTED_ARG_TO_UNRESOLVED_CALL", "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
            "RETURN_TAINTED_VALUE", "TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN",
            "TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG",
            "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN"
        ]
        cpu_flag_core_names_for_json = [
            "tmpcy", "ng", "zf", "cf", "of", "sf", "pf", "tmpnz", "tmpov", "tmpca", "af", 
            "cc_n", "cc_z", "cc_c", "cc_v"
        ]

        all_simplified_usages = [] 
        for usage in self.all_tainted_usages:
            should_include_this_usage = False
            current_usage_type = usage.get("usage_type")
            if current_usage_type in included_usage_types_for_json:
                should_include_this_usage = True
                if current_usage_type == "BRANCH_CONDITION_TAINTED":
                    is_cpu_flag_component = False
                    tainted_comp_repr = usage.get("tainted_component_repr", "")
                    lc_tainted_comp_repr = tainted_comp_repr.lower()
                    for flag_name in cpu_flag_core_names_for_json:
                        if "({}".format(flag_name) in lc_tainted_comp_repr and lc_tainted_comp_repr.endswith(")"):
                            last_paren_open_idx = lc_tainted_comp_repr.rfind('(')
                            if last_paren_open_idx != -1 and lc_tainted_comp_repr[-1] == ')':
                                content_in_paren = lc_tainted_comp_repr[last_paren_open_idx+1:-1]
                                if content_in_paren == flag_name:
                                    is_cpu_flag_component = True; break
                        if lc_tainted_comp_repr == flag_name:
                            is_cpu_flag_component = True; break
                    if is_cpu_flag_component:
                        should_include_this_usage = False
            if not should_include_this_usage: continue

            usage_entry_for_json = {
                "originating_imported_function_name": usage.get("originating_imported_function_name", "Unknown_Origin"),
                "found_in_function_name": usage.get("function_name", "N/A"),
                "found_in_function_entry": usage.get("function_entry", "N/A"),
                "instruction_address": usage.get("address", "N/A"),
                "pcode_operation": usage.get("pcode_op_str", "N/A"),
                "usage_type": usage.get("usage_type", "N/A"),
                "tainted_component": usage.get("tainted_component_repr", "N/A")
            }
            if "details" in usage and usage["details"] is not None:
                usage_entry_for_json["details"] = usage["details"]
            if usage.get("usage_type") == "STORE_TAINTED_VALUE" and "destination_repr" in usage:
                usage_entry_for_json["store_destination"] = usage["destination_repr"]
            if usage.get("usage_type") == "BRANCH_CONDITION_TAINTED" and "compared_operands" in usage:
                usage_entry_for_json["branch_compared_operands"] = usage["compared_operands"]
            all_simplified_usages.append(usage_entry_for_json)

        try:
            with open(output_file_path, 'w') as f:
                json.dump(all_simplified_usages, f, indent=4)
            self.println("Taint analysis results saved to: {}".format(output_file_path))
        except IOError as e:
            self.printerr("Failed to write JSON output to file {}: {}".format(output_file_path, e))
        except Exception as e:
            self.printerr("An unexpected error occurred while writing JSON output: {}".format(e))
    
    # -------------------
    # Main Public Method
    # -------------------
    def run(self, target_keyword):
        self.println("INFO: Searching for functions, thunks, and call sites related to keyword '{}'".format(target_keyword))

        target_ext_funcs = []
        ext_funcs_iter = self.func_manager.getExternalFunctions()
        while ext_funcs_iter.hasNext():
            ext_func = ext_funcs_iter.next()
            if target_keyword in ext_func.getName():
                target_ext_funcs.append(ext_func)

        if not target_ext_funcs:
            self.printerr("ERROR: No external function found with keyword '{}'. Exiting.".format(target_keyword))
            return

        all_callable_targets = set(target_ext_funcs)
        for ext_func in target_ext_funcs:
            self.println("INFO: Found external function '{}'. Searching for its thunks.".format(ext_func.getName()))
            all_funcs_iter = self.func_manager.getFunctions(True)
            while all_funcs_iter.hasNext():
                f = all_funcs_iter.next()
                if f.isThunk():
                    thunked_func = f.getThunkedFunction(True)
                    if thunked_func and thunked_func.equals(ext_func):
                        self.println("INFO: Found thunk '{}' at {} for external function.".format(f.getName(), f.getEntryPoint()))
                        all_callable_targets.add(f)

        all_call_sites = set()
        for target in all_callable_targets:
            refs = self.ref_manager.getReferencesTo(target.getEntryPoint())
            for ref in refs:
                if ref.getReferenceType().isCall():
                    all_call_sites.add(ref.getFromAddress())

        if not all_call_sites:
            self.printerr("ERROR: No call sites found for any targets related to keyword '{}'.".format(target_keyword))
            return
            
        self.println("INFO: Found {} unique call sites. Analyzing each...".format(len(all_call_sites)))
        
        for call_site_addr in sorted(list(all_call_sites), key=lambda addr: addr.getOffset()):
            self.println("\\n--- Analyzing Call Site #{} at {} ---".format(call_site_addr.getOffset(), call_site_addr))
            
            parent_func = self.func_manager.getFunctionContaining(call_site_addr)
            if not parent_func:
                self.printerr("ERROR: No parent function for call site {}. Skipping.".format(call_site_addr))
                continue
            
            self.println("DEBUG: Parent (caller): {} at {}".format(parent_func.getName(), parent_func.getEntryPoint()))
            
            decompile_results = self.decompiler.decompileFunction(parent_func, 60, self.monitor)
            if not decompile_results or not decompile_results.getHighFunction():
                self.printerr("ERROR: Failed to decompile {}. Skipping.".format(parent_func.getName()))
                continue
            
            high_parent_func = decompile_results.getHighFunction()
            
            target_call_op = None
            op_iter = high_parent_func.getPcodeOps(call_site_addr)
            while op_iter.hasNext():
                pcode_op = op_iter.next()
                if pcode_op.getMnemonic() in ["CALL", "CALLIND"]:
                    target_call_op = pcode_op
                    break
            
            if not target_call_op:
                self.printerr("ERROR: No CALL/CALLIND PcodeOp found at call site: {}. Skipping.".format(call_site_addr))
                continue
            
            output_vn = target_call_op.getOutput()
            if not output_vn:
                self.println("INFO: Call at {} has no output varnode. Nothing to taint. Skipping.".format(call_site_addr))
                continue
                
            output_hv = output_vn.getHigh()
            if not output_hv:
                self.println("INFO: Call at {} has no HighVariable for its output. Nothing to taint. Skipping.".format(call_site_addr))
                continue

            current_initial_taint_source_hv_set = {output_hv}
            
            self.println("\\n--- Initiating Taint Analysis for: {} (call at {}) ---".format(parent_func.getName(), call_site_addr))
            self.println("DEBUG: Taint source is the return value of the call: {}".format(self._get_varnode_representation(output_hv, high_parent_func)))

            self._trace_taint_in_function(
                high_parent_func, current_initial_taint_source_hv_set, target_call_op,
                originating_imported_func_name_for_log=target_keyword,
                current_depth=0
            )
    
        if not all_call_sites: 
            self.println("INFO: No call sites processed for keyword '{}'.".format(target_keyword))

        self.println("\\n--- Taint Analysis Run Complete ---")
        if self.all_tainted_usages:
            self._print_results()
            self._save_results_to_json()
        else:
            self.println("No tainted value usages detected for keyword '{}'.".format(target_keyword))


# -------------------
# Main script entry point (Ghidra script boilerplate)
# -------------------
def run_analysis_from_ghidra_ui():
    """
    This function is the main entry point when run from Ghidra's UI.
    It sets up the environment and kicks off the analysis.
    This is a placeholder in the generic engine and should be implemented
    by the specific analyzer script that uses this engine.
    """
    _println = globals().get('println', lambda msg: sys.stdout.write(str(msg) + "\n"))
    _println("This is the generic taint analysis engine.")
    _println("It is not meant to be run directly.")
    _println("Please run a specific analysis script (e.g., mnn_analyzer.py) which uses this engine.")
    return


if __name__ == "__main__":
    if 'currentProgram' in globals() and globals().get('currentProgram') is not None:
        run_analysis_from_ghidra_ui()
    else:
        print("This script is designed to be run from within Ghidra's Script Manager.")
    
    _final_println = globals().get('println', lambda x: None)
    _final_println("analyze_mnn_taint_modular.py finished.") 