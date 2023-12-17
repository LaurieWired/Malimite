# Import Ghidra modules
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import FunctionManager
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.mem import Memory
from ghidra.program.model.listing import Listing
import os
import json

outputPath = "C:\\Users\\Laurie\\Documents\\GitClones\\Dev_ipax\\test_samples\\temp"  #FIXME
dataOutputFile = "C:\\Users\\Laurie\\Documents\\GitClones\\Dev_ipax\\test_samples\\temp\\ipax_macho_data.json"  #FIXME

def format_namespace_name(namespace_name):
    if namespace_name == "<global>":
        return "Global"
    elif namespace_name == "<EXTERNAL>":
        return "External"
    return namespace_name

def list_functions_and_namespaces(program):
    functionManager = program.getFunctionManager()
    decompInterface = DecompInterface()
    decompInterface.openProgram(program)
    namespaceFunctionsMap = {}

    # Ensure the output directory exists
    if not os.path.exists(outputPath):
        os.makedirs(outputPath)

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
        filePath = os.path.join(outputPath, "{}.cpp".format(namespace))
        with open(filePath, 'w') as file:
            file.write("class {} {{\n".format(namespace))
            for function in functions:
                decompiledFunction = decompInterface.decompileFunction(function, 0, ConsoleTaskMonitor())
                decompiledCode = decompiledFunction.getDecompiledFunction().getC() if decompiledFunction.decompileCompleted() else "// Unable to decompile function"
                file.write(decompiledCode)
            file.write("}\n")  # Close the namespace

    # Close the decompiler interface
    decompInterface.closeProgram()

def list_defined_data_in_all_segments(program):
    memory = program.getMemory()
    listing = program.getListing()
    segments = memory.getBlocks()

    dataStructure = {}

    # Iterate over all segments
    for segment in segments:
        start = segment.getStart()
        end = segment.getEnd()
        name = segment.getName()
        
        # Create a dictionary for each segment
        segmentData = {
            "start": str(start),
            "end": str(end),
            "data": []
        }

        # Iterate over defined data in each segment
        dataIterator = listing.getDefinedData(start, True)
        for data in dataIterator:
            # Ensure the data is within the current segment
            if not segment.contains(data.getAddress()):
                continue

            label = data.getLabel()
            value = data.getDefaultValueRepresentation()
            address = str(data.getAddress())

            # Append data to the segment's data list
            dataEntry = {
                "label": label if label else "Unnamed",
                "value": value,
                "address": address
            }
            segmentData["data"].append(dataEntry)

        # Add the segment to the data structure
        dataStructure[name] = segmentData

    # Write the JSON to the file
    with open(dataOutputFile, 'w') as file:
        json.dump(dataStructure, file, indent=4)
                
# Write the decompilation and the data to disk to be read in by ipax
list_functions_and_namespaces(currentProgram)
list_defined_data_in_all_segments(currentProgram)