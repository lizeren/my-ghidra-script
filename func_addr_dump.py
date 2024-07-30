# Dump function startiong address
#
# @category xref.Demo
#
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def export_function_info_to_files():
    # Initialize the decompiler
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)

    # Create a task monitor
    monitor = ConsoleTaskMonitor()

    # Get the function manager from the current program
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True to iterate forward through functions

    # Prepare to collect function data
    functions_data = []

    # Iterate over all functions
    for function in functions:
        # Get the entry point address and the name of the function
        function_entry = str(function.getEntryPoint())
        function_entry = hex(int(("0x"+ function_entry[3:]),16))
        function_name = function.getName()

        # Collect function info for JSON output
        functions_data.append({
            "name": function_name,
            "entry_point": function_entry
        })

    # Write the collected data to a JSON file
    with open("/home/lizeren/Desktop/static_analyzer/output/dec_functions_list.json", "w") as json_file:
        json.dump(functions_data, json_file, indent=4)

# Call the function to export function names and addresses to files
export_function_info_to_files()
