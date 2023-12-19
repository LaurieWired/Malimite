# Import Ghidra modules
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import FunctionManager
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.mem import Memory
from ghidra.program.model.listing import Listing
import os
import json

# Function to get command-line arguments in Ghidra headless mode
def get_output_path():
    args = getScriptArgs()
    if len(args) > 0:
        return args[0]
    else:
        print("No output path provided. Exiting script.")
        return None

def format_namespace_name(namespace_name):
    if namespace_name == "<global>":
        return "Global"
    elif namespace_name == "<EXTERNAL>":
        return "External"
    return namespace_name

# TODO: Slow for very large files. May want to rethink this design
def list_functions_and_namespaces(program, outputPath):
    functionManager = program.getFunctionManager()
    decompInterface = DecompInterface()
    decompInterface.openProgram(program)
    namespaceFunctionsMap = {}

    # Collect functions for each namespace
    for function in functionManager.getFunctions(True):  # True for forward direction
        namespace = function.getParentNamespace()
        namespace_name = format_namespace_name(namespace.getName() if namespace else "<global>")
        
        # Add function to the map
        if namespace_name not in namespaceFunctionsMap:
            namespaceFunctionsMap[namespace_name] = []
        namespaceFunctionsMap[namespace_name].append(function)

    # Write to files
    for namespace, functions in namespaceFunctionsMap.items():
        filePath = os.path.join(outputPath, "{}.c".format(namespace))
        with open(filePath, 'w') as file:
            file.write("class {} {{\n".format(namespace))
            for function in functions:
                decompiledFunction = decompInterface.decompileFunction(function, 0, ConsoleTaskMonitor())
                decompiledCode = decompiledFunction.getDecompiledFunction().getC() if decompiledFunction.decompileCompleted() else "// Unable to decompile function"
                file.write(decompiledCode)
            file.write("}\n")  # Close the namespace

    # Close the decompiler interface
    decompInterface.closeProgram()
               

def main():
    outputPath = get_output_path()
    if outputPath is None:
        return  # Exit if no output path is provided

    # Ensure the output directory exists
    if not os.path.exists(outputPath):
        os.makedirs(outputPath)

    # Write the decompilation to disk to be read in by ipax
    list_functions_and_namespaces(currentProgram, outputPath)

# Run the main function
if __name__ == "__main__":
    main()