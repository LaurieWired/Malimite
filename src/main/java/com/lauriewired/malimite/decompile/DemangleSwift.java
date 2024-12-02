package com.lauriewired.malimite.decompile;

import java.util.logging.Logger;
import java.util.logging.Level;

public class DemangleSwift {
    private static final Logger LOGGER = Logger.getLogger(DemangleSwift.class.getName());

    public static class DemangledName {
        public final String className;
        public final String fullMethodName;

        public DemangledName(String className, String fullMethodName) {
            this.className = className;
            this.fullMethodName = fullMethodName;
        }
    }

    public static DemangledName demangleSwiftName(String mangledName) {
        if (mangledName == null || !mangledName.startsWith("_$s")) {
            return null; // Not a valid Swift mangled name
        }

        try {
            // Drop the _$s prefix
            String remaining = mangledName.substring(3);

            // Extract the class name
            int classNameLength = extractNumber(remaining);
            String className = remaining.substring(String.valueOf(classNameLength).length(),
                                                   String.valueOf(classNameLength).length() + classNameLength);

            // Move past the class name
            remaining = remaining.substring(String.valueOf(classNameLength).length() + classNameLength);

            // Extract the method name
            StringBuilder methodNameBuilder = new StringBuilder();

            while (!remaining.isEmpty()) {
                // Skip leading zeros and extract the next number
                int numberIndex = findNextNumberIndex(remaining);
                if (numberIndex == -1) break; // No more numbers, exit loop

                String remainingAfterNumber = remaining.substring(numberIndex);
                int length = extractNumber(remainingAfterNumber);

                // Skip the number itself in the string
                int numberLength = String.valueOf(length).length();
                String segment = remainingAfterNumber.substring(numberLength, numberLength + length);
                methodNameBuilder.append(segment);

                // Update the remaining string
                remaining = remainingAfterNumber.substring(numberLength + length);
            }

            String methodName = methodNameBuilder.toString();
            return new DemangledName(className, methodName);
        } catch (Exception e) {
            System.err.println("Failed to demangle Swift name: " + mangledName);
            e.printStackTrace();
        }

        return null;
    }

    private static int findNextNumberIndex(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (Character.isDigit(str.charAt(i)) && str.charAt(i) != '0') {
                return i; // Return index of the first non-zero digit
            }
        }
        return -1; // No valid number found
    }

    private static int extractNumber(String str) {
        StringBuilder numberBuilder = new StringBuilder();
        boolean leadingZeroSkipped = false;

        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isDigit(c)) {
                if (c != '0' || leadingZeroSkipped) {
                    numberBuilder.append(c);
                    leadingZeroSkipped = true;
                }
            } else {
                break; // Stop when we reach a non-digit
            }
        }
        return numberBuilder.length() > 0 ? Integer.parseInt(numberBuilder.toString()) : 0;
    }
} 