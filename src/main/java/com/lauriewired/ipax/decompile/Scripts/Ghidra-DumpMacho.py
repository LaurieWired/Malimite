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

# Helper function to count lines in a string
def count_lines(s):
    return s.count('\n') + 1

def list_functions_and_namespaces(program, outputPath):
    functionManager = program.getFunctionManager()
    decompInterface = DecompInterface()
    decompInterface.openProgram(program)
    namespaceFunctionsMap = {}
    jsonOutput = []

    # Collect functions for each namespace
    for function in functionManager.getFunctions(True):  # True for forward direction
        namespace = function.getParentNamespace()
        namespace_name = format_namespace_name(namespace.getName() if namespace else "<global>")
        
        # Add function to the map
        if namespace_name not in namespaceFunctionsMap:
            namespaceFunctionsMap[namespace_name] = []
        namespaceFunctionsMap[namespace_name].append(function)

    # Initialize a counter for file naming
    fileCounter = 1

    # Write to files with names based on the counter
    for namespace, functions in namespaceFunctionsMap.items():
        filePath = os.path.join(outputPath, "ipax_class_{}.c".format(fileCounter))

        with open(filePath, 'w') as file:
            file.write("class {} {{\n".format(namespace))

            for function in functions:
                decompiledFunction = decompInterface.decompileFunction(function, 0, ConsoleTaskMonitor())
                if decompiledFunction.decompileCompleted():
                    decompiledCode = decompiledFunction.getDecompiledFunction().getC()
                    file.write(decompiledCode)
                    jsonOutput.append({
                        "FunctionName": function.getName(),
                        "ClassName": namespace,
                        "ClassFileName": os.path.basename(filePath),
                    })
                else:
                    file.write("// Unable to decompile function\n")
            file.write("}\n")  # Close the namespace

        # Increment the counter after writing each file
        fileCounter += 1

    # Write JSON output
    jsonFilePath = os.path.join(outputPath, "functions_info.json")
    with open(jsonFilePath, 'w') as jsonFile:
        json.dump(jsonOutput, jsonFile, indent=4)

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
