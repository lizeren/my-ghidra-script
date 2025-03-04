# Dump functions to file named after them
#
# @category xref.Demo
#

# Import the necessary Ghidra modules
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
from java.io import FileWriter
import os

OUTPUT_DIR = "/home/lizeren/Download"

def decompile_function(function):
    """
    Decompile the specified function and return the decompiled text.
    """
    if not function:
        print("No function was provided to decompile.")
        return None

    # Initialize the decprintHelloam(currentProgram)

    # Decompile the function
    results = decompiler.decompileFunction(function, 0, ConsoleTaskMonitor())
    if results.decompileCompleted():
        decompiled_text = results.getDecompiledFunction().getC()
    else:
        print("Decompilation failed for function: {}".format(function.getName()))
        return None

    decompiler.dispose()
    return decompiled_text

def save_decompiled_code(function_name, code):
    """
    Save the decompiled code to a .c file named after the function.
    """
    # Ensure the output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    file_path = os.path.join(OUTPUT_DIR, "{}.c".format(function_name))
    with open(file_path, 'w') as file:
        file.write(code)
    print("Decompiled code saved to: {}".format(file_path))

def main():
    # Iterate over all functions in the current program
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True) # True to iterate forward
    for function in functions:
        function_name = function.getName()
        if function.getSymbol().getSource() != SourceType.DEFAULT:
            # Only process user-defined or imported functions
            decompiled_code = decompile_function(function)
            if decompiled_code:
                save_decompiled_code(function_name, decompiled_code)

# Entry point
if __name__ == "__main__":
    main()
