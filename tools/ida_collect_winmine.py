import json
import os
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import idautils
import idc


TARGET_IMPORTS = {
    "rand",
    "srand",
    "GetTickCount",
    "SetTimer",
    "KillTimer",
    "InvalidateRect",
    "SetCapture",
    "ReleaseCapture",
    "PtInRect",
    "CreateWindowExW",
    "RegisterClassW",
    "DialogBoxParamW",
    "BitBlt",
    "SetDIBitsToDevice",
    "SetPixel",
    "PlaySoundW",
    "RegQueryValueExW",
    "RegSetValueExW",
}


def hx(ea):
    return "0x%08X" % ea


def safe_name(ea):
    return ida_name.get_name(ea) or idc.get_func_name(ea) or hx(ea)


def insn_text(ea):
    return idc.generate_disasm_line(ea, 0) or ""


def func_bounds(ea):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return None
    return {
        "start": hx(fn.start_ea),
        "end": hx(fn.end_ea),
        "name": safe_name(fn.start_ea),
        "size": fn.end_ea - fn.start_ea,
    }


def disasm_window(ea, before=8, after=12):
    items = list(idautils.FuncItems(ida_funcs.get_func(ea).start_ea)) if ida_funcs.get_func(ea) else []
    if ea not in items:
        return [{"ea": hx(ea), "text": insn_text(ea)}]
    idx = items.index(ea)
    out = []
    for cur in items[max(0, idx - before): min(len(items), idx + after + 1)]:
        out.append({"ea": hx(cur), "text": insn_text(cur)})
    return out


def decompile_func(start_ea):
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(start_ea)
        if not cfunc:
            return None
        return str(cfunc)
    except Exception as exc:
        return "DECOMPILE_ERROR: %s" % exc


def collect_imports():
    imports = []
    by_name = {}

    def cb(ea, name, ordinal):
        item = {
            "ea": hx(ea),
            "name": name or ("ordinal_%d" % ordinal),
            "ordinal": ordinal,
        }
        imports.append(item)
        if name:
            by_name.setdefault(name, []).append(ea)
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i) or ("module_%d" % i)
        before = len(imports)
        ida_nalt.enum_import_names(i, cb)
        for item in imports[before:]:
            item["module"] = mod
    return imports, by_name


def collect_segments():
    segs = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        segs.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hx(seg.start_ea),
            "end": hx(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
        })
    return segs


def collect_strings():
    ss = idautils.Strings()
    ss.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])
    out = []
    for s in ss:
        text = str(s)
        if len(text) >= 4:
            out.append({"ea": hx(s.ea), "type": s.strtype, "text": text})
    return out


def collect_target_xrefs(imports_by_name):
    xrefs = {}
    funcs = {}
    for name in sorted(TARGET_IMPORTS):
        hits = []
        for iat_ea in imports_by_name.get(name, []):
            for xr in idautils.XrefsTo(iat_ea, 0):
                fn = func_bounds(xr.frm)
                hit = {
                    "from": hx(xr.frm),
                    "to_iat": hx(iat_ea),
                    "line": insn_text(xr.frm),
                    "function": fn,
                    "window": disasm_window(xr.frm),
                }
                hits.append(hit)
                if fn:
                    funcs[int(fn["start"], 16)] = fn
        xrefs[name] = hits
    return xrefs, funcs


def collect_functions():
    out = []
    for ea in idautils.Functions():
        fn = ida_funcs.get_func(ea)
        out.append({
            "start": hx(fn.start_ea),
            "end": hx(fn.end_ea),
            "name": safe_name(fn.start_ea),
            "size": fn.end_ea - fn.start_ea,
        })
    return out


def collect_data_refs_for_functions(funcs):
    out = {}
    for start in sorted(funcs):
        refs = []
        for ea in idautils.FuncItems(start):
            for idx in range(2):
                op_type = idc.get_operand_type(ea, idx)
                if op_type in (idc.o_mem, idc.o_displ, idc.o_imm):
                    val = idc.get_operand_value(ea, idx)
                    if 0x01000000 <= val < 0x01020000:
                        refs.append({
                            "ea": hx(ea),
                            "line": insn_text(ea),
                            "op": idx,
                            "value": hx(val),
                            "name": safe_name(val),
                        })
        out[hx(start)] = refs
    return out


def write_text(path, data):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def main():
    ida_auto.auto_wait()

    out_dir = os.environ.get("WINMINE_ANALYSIS_DIR")
    if not out_dir:
        out_dir = os.path.abspath("analysis")
    os.makedirs(out_dir, exist_ok=True)

    imports, imports_by_name = collect_imports()
    xrefs, relevant_funcs = collect_target_xrefs(imports_by_name)
    functions = collect_functions()
    segments = collect_segments()
    strings = collect_strings()
    data_refs = collect_data_refs_for_functions(relevant_funcs)

    decompiled = {}
    disassembly = {}
    for start in sorted(relevant_funcs):
        fn = ida_funcs.get_func(start)
        if not fn:
            continue
        lines = []
        for ea in idautils.FuncItems(start):
            lines.append("%s  %s" % (hx(ea), insn_text(ea)))
        key = "%s_%s" % (hx(start), safe_name(start))
        disassembly[key] = "\n".join(lines)
        decompiled[key] = decompile_func(start)

    report = {
        "input_file": ida_nalt.get_input_file_path(),
        "imagebase": hx(ida_nalt.get_imagebase()),
        "segments": segments,
        "imports": imports,
        "target_xrefs": xrefs,
        "relevant_functions": list(relevant_funcs.values()),
        "functions": functions,
        "strings": strings,
        "data_refs_in_relevant_functions": data_refs,
    }

    with open(os.path.join(out_dir, "ida_summary.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "ida_disassembly.json"), "w", encoding="utf-8") as f:
        json.dump(disassembly, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "ida_decompiled.json"), "w", encoding="utf-8") as f:
        json.dump(decompiled, f, ensure_ascii=False, indent=2)

    write_text(os.path.join(out_dir, "ida_done.txt"), "IDA collection completed\n")
    idc.qexit(0)


try:
    main()
except Exception:
    out_dir = os.environ.get("WINMINE_ANALYSIS_DIR") or os.path.abspath("analysis")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "ida_error.txt"), "w", encoding="utf-8") as f:
        f.write(traceback.format_exc())
    idc.qexit(1)
