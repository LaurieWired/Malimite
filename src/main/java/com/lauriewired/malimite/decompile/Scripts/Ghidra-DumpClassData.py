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
    
def extract_class_function_data(program, outputPath):
    functionManager = program.getFunctionManager()
    classFunctionData = []

    # Temporary dictionary to hold the namespace and functions
    namespaceFunctionData = {}

    # Collect functions for each namespace
    for function in functionManager.getFunctions(True):  # True for forward direction
        namespace = function.getParentNamespace()
        namespace_name = format_namespace_name(namespace.getName() if namespace else "<global>")
        
        if namespace_name not in namespaceFunctionData:
            namespaceFunctionData[namespace_name] = []

        functionName = function.getName()
        namespaceFunctionData[namespace_name].append(functionName)

    # Convert to desired format
    for className, functions in namespaceFunctionData.items():
        classFunctionData.append({
            "ClassName": className,
            "Functions": json.dumps(functions)
        })

    # Write the class-function data to JSON
    classDataFilePath = os.path.join(outputPath, "malimite_class_data.json")
    with open(classDataFilePath, 'w') as file:
        json.dump(classFunctionData, file, indent=4)

def list_defined_data_in_all_segments(program, outputPath):
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
    dataOutputFile = os.path.join(outputPath, "malimite_macho_data.json")
    with open(dataOutputFile, 'w') as file:
        json.dump(dataStructure, file, indent=4)
                

def main():
    outputPath = get_output_path()
    if outputPath is None:
        return  # Exit if no output path is provided

    # Ensure the output directory exists
    if not os.path.exists(outputPath):
        os.makedirs(outputPath)

    # Write the class data and data segment data to disk to be read in by malimite
    extract_class_function_data(currentProgram, outputPath)
    list_defined_data_in_all_segments(currentProgram, outputPath)

# Run the main function
if __name__ == "__main__":
    main()
