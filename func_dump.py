# Output all the decompiled functions and their entry point(starting memory address)
#
# @category xref.Demo
#

# Import necessary Ghidra modules
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def get_decompiled_function_info():
    # Initialize the decompiler
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)

    # Create a task monitor
    monitor = ConsoleTaskMonitor()

    # Get the function manager from the current program
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True) # True to iterate forward through functions

    # Iterate over all functions
    for function in functions:
        # Get the entry point address and the name of the function
        function_entry = function.getEntryPoint()
        function_name = function.getName()

        # Attempt to decompile the function
        decomp_result = decomp_interface.decompileFunction(function, 0, monitor)

        # Check if decompilation was successful
        if decomp_result.decompileCompleted():
            print("Function Name: {}, Entry Point: {}".format(function_name, function_entry))
        else:
            print("Failed to decompile Function: {}, Entry Point: {}".format(function_name, function_entry))

# Call the function to print decompiled function names and addresses
get_decompiled_function_info()
