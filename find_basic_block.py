# Import Ghidra modules
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

# Create a new BasicBlockModel, which is used to access basic blocks
basicBlockModel = BasicBlockModel(currentProgram)

# Create a monitor object (similar to a progress bar)
monitor = ConsoleTaskMonitor()

# Retrieve all functions in the current program
functionManager = currentProgram.getFunctionManager()
functions = functionManager.getFunctions(True) # True to iterate forward through the functions

# Loop through all functions
for function in functions:
    print("Function Name: {}, Entry Point: {}".format(function.getName(), function.getEntryPoint()))

    # Retrieve the basic blocks for the current function
    blocks = basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor)

    # Loop through each block in the function
    for block in blocks:
        start = block.getFirstStartAddress()
        num_instructions = block.getNumAddresses()
        print("\tBasic Block Start: {}, Instruction Count: {}".format(start, num_instructions))

print("Basic block analysis completed.")
