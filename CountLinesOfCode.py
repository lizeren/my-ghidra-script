#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @category xref.Demo

import json
import os
import time
from java.io import File, FileWriter
from ghidra.program.model.listing import Listing

def count_instructions(func, listing):
    """Count instructions via Ghidra’s InstructionIterator."""
    body = func.getBody()
    if body is None or body.isEmpty():
        return 0
    instr_iter = listing.getInstructions(body, True)
    count = 0
    while instr_iter.hasNext():
        instr_iter.next()
        count += 1
    return count

def save_json(data, path):
    """Save dict `data` as JSON at `path`, creating parent dirs if needed."""
    directory = os.path.dirname(path)
    if directory:
        dir_file = File(directory)
        if not dir_file.exists():
            dir_file.mkdirs()
    writer = FileWriter(File(path))
    try:
        writer.write(json.dumps(data, indent=2))
    finally:
        writer.close()
    print "Saved JSON to %s" % path

def run():
    print "="*60
    print "COUNTING INSTRUCTIONS PER FUNCTION"
    print "="*60
    start = time.time()


    listing = currentProgram.getListing()
    funcs   = currentProgram.getFunctionManager().getFunctions(True)

    results     = {}
    total_instr = 0
    func_count  = 0

    for f in funcs:
        if f.isExternal():
            continue
        func_count += 1
        instr_count = count_instructions(f, listing)
        results[f.getName(False)] = instr_count
        total_instr += instr_count

    # Load the STPL JSON(mangled name -> original name in src)

    # yosys-abc
    # stpl_path = "/mnt/linuxstorage/vlsi-open-source-tool/output/yosys/yosys-abc/STPL.json"

    # stpl_percentage_test_case
    # stpl_path = "/mnt/linuxstorage/vlsi-open-source-tool/clang_study/stpl_percentage_test_case/analysis/stpl.json"

    # opentimer ot-shell
    # stpl_path = "/mnt/linuxstorage/vlsi-open-source-tool/output/opentimer/ot-shell/STPL.json"

    # OpenSTA
    stpl_path = "/mnt/linuxstorage/vlsi-open-source-tool/output/opensta/STPL.json"

    try:
        with open(stpl_path, 'r') as f:
            stpl_map = json.load(f)
    except Exception as e:
        print "Error loading STPL.json: %s" % e
        stpl_map = {}

    # Sum instructions for functions listed in STPL.json
    stpl_instr = 0
    missing    = []
    for mangled_name,original_name in stpl_map.items():
        count = results.get(original_name)
        if count is None:
            print("this should not happen,mangled_name:%s,original_name:%s", mangled_name, original_name)
            missing.append(mangled_name)
        else:
            stpl_instr += count

    # Compute ratio
    ratio = float(stpl_instr) / total_instr if total_instr > 0 else 0.0


    # yosys-abc
    # output_path = "/mnt/linuxstorage/vlsi-open-source-tool/output/yosys/yosys-abc/LoC.json"
    
    # stpl_percentage_test_case
    # output_path = "/mnt/linuxstorage/vlsi-open-source-tool/clang_study/stpl_percentage_test_case/analysis/LoC.json"

    # opentimer ot-shell
    # output_path = "/mnt/linuxstorage/vlsi-open-source-tool/output/opentimer/ot-shell/LoC.json"

    # OpenSTA
    output_path = "/mnt/linuxstorage/vlsi-open-source-tool/output/opensta/LoC.json"

    save_json(results, output_path)

    # Print summary
    elapsed = time.time() - start
    print ""
    print "Processed %d functions, %d total instructions in %.2f seconds" % (
        func_count, total_instr, elapsed)
    print "-"
    print "S_TPL Function count: %d" % len(stpl_map)
    print "Total S_TPL instructions: %d" % stpl_instr
    print "S_TPL instructions / All instructions ratio: %d / %d = %.4f" % (stpl_instr, total_instr, ratio)
    print "="*60

run()
