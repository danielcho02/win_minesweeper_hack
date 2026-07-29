import json
import os
import traceback

import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_name
import idautils
import idc


DATA_POINTS = {
    "game_flags": 0x01005000,
    "click_col": 0x01005118,
    "click_row": 0x0100511C,
    "face_state": 0x01005160,
    "mine_counter": 0x01005330,
    "board_width": 0x01005334,
    "board_height": 0x01005338,
    "board": 0x01005340,
    "level": 0x010056A0,
    "custom_mines": 0x010056A4,
    "custom_height": 0x010056A8,
    "custom_width": 0x010056AC,
    "timer_started": 0x0100579C,
    "game_over": 0x010057A4,
}


BOARD_START = 0x01005340
BOARD_END = 0x010056A0


def hx(ea):
    return "0x%08X" % ea


def name(ea):
    return ida_name.get_name(ea) or idc.get_func_name(ea) or hx(ea)


def line(ea):
    return idc.generate_disasm_line(ea, 0) or ""


def decompile(start):
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(start)
        return str(cfunc) if cfunc else None
    except Exception as exc:
        return "DECOMPILE_ERROR: %s" % exc


def func_info(ea):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return None
    return {
        "start": hx(fn.start_ea),
        "end": hx(fn.end_ea),
        "name": name(fn.start_ea),
        "size": fn.end_ea - fn.start_ea,
    }


def operand_refs():
    funcs = {}
    refs = []
    for fea in idautils.Functions():
        fn = ida_funcs.get_func(fea)
        for ea in idautils.FuncItems(fea):
            for op in range(3):
                typ = idc.get_operand_type(ea, op)
                if typ in (idc.o_mem, idc.o_displ, idc.o_imm):
                    val = idc.get_operand_value(ea, op)
                    label = None
                    for key, addr in DATA_POINTS.items():
                        if val == addr:
                            label = key
                            break
                    if label is None and BOARD_START <= val < BOARD_END:
                        label = "board_range"
                    if label:
                        info = func_info(ea)
                        if info:
                            funcs[int(info["start"], 16)] = info
                        refs.append({
                            "ea": hx(ea),
                            "line": line(ea),
                            "operand": op,
                            "value": hx(val),
                            "label": label,
                            "function": info,
                        })
    return refs, funcs


def collect_function_text(funcs):
    disasm = {}
    decomp = {}
    for start in sorted(funcs):
        fn = ida_funcs.get_func(start)
        if not fn:
            continue
        key = "%s_%s" % (hx(start), name(start))
        rows = []
        for ea in idautils.FuncItems(start):
            rows.append("%s  %s" % (hx(ea), line(ea)))
        disasm[key] = "\n".join(rows)
        decomp[key] = decompile(start)
    return disasm, decomp


def main():
    ida_auto.auto_wait()
    out_dir = os.environ.get("WINMINE_ANALYSIS_DIR") or os.path.abspath("analysis")
    os.makedirs(out_dir, exist_ok=True)
    refs, funcs = operand_refs()
    disasm, decomp = collect_function_text(funcs)
    result = {
        "input_file": ida_nalt.get_input_file_path(),
        "data_points": {k: hx(v) for k, v in DATA_POINTS.items()},
        "board_stride": 32,
        "board_start": hx(BOARD_START),
        "board_end": hx(BOARD_END),
        "refs": refs,
        "functions": list(funcs.values()),
    }
    with open(os.path.join(out_dir, "ida_board_refs.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "ida_board_disassembly.json"), "w", encoding="utf-8") as f:
        json.dump(disasm, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "ida_board_decompiled.json"), "w", encoding="utf-8") as f:
        json.dump(decomp, f, ensure_ascii=False, indent=2)
    idc.qexit(0)


try:
    main()
except Exception:
    out_dir = os.environ.get("WINMINE_ANALYSIS_DIR") or os.path.abspath("analysis")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "ida_board_error.txt"), "w", encoding="utf-8") as f:
        f.write(traceback.format_exc())
    idc.qexit(1)
