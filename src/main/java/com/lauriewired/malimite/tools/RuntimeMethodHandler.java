package com.lauriewired.malimite.tools;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class RuntimeMethodHandler {
    private static final Map<String, Set<String>> methodCategories = new HashMap<>();

    static {
        // Object Retain/Release
        addCategory("Object Retain/Release",
            "_swift_retain",
            "_swift_retain_n",
            "_swift_release",
            "_swift_release_n",
            "_swift_bridgeObjectRelease",
            "_swift_unknownObjectRelease",
            "_swift_unownedRetain",
            "_swift_unownedRelease",
            "_swift_retainCount",
            "_swift_bridgeObjectRetain",
            "_swift_unknownObjectRetain"
        );

        // Dynamic Casting and Type Checking
        addCategory("Dynamic Casting",
            "_swift_dynamicCast",
            "_swift_dynamicCastClass",
            "_swift_dynamicCastClassUnconditional",
            "_swift_dynamicCastObjCClass",
            "_swift_dynamicCastObjCClassUnconditional",
            "_swift_dynamicCastMetatype",
            "_swift_dynamicCastMetatypeUnconditional",
            "_swift_isClassOrObjCExistentialType",
            "_swift_getGenericMetadata",
            "_swift_getGenericWitnessTable"
        );

        // Memory Management
        addCategory("Memory Management",
            "_swift_allocObject",
            "_swift_deallocObject",
            "_swift_slowAlloc",
            "_swift_slowDealloc",
            "_swift_slowAllocArray",
            "_swift_bufferAllocate",
            "_swift_bufferDeallocate",
            "_swift_bufferHeaderInit",
            "_swift_bufferInitialize",
            "_swift_bufferDestroy"
        );

        // String and Character
        addCategory("String Operations",
            "_swift_convertStringToNSString",
            "_swift_convertNSStringToString",
            "_swift_convertStringToCString",
            "_swift_convertCStringToString",
            "_swift_bridgeNSStringToString",
            "_swift_isStringEmpty",
            "_swift_strlen",
            "_swift_getStringLength"
        );

        // Existentials
        addCategory("Existentials",
            "_swift_existentialRetain",
            "_swift_existentialRelease",
            "_swift_getExistentialTypeMetadata",
            "_swift_getExistentialMetatype",
            "_swift_getDynamicType"
        );

        // Concurrency
        addCategory("Concurrency",
            "_swift_task_create",
            "_swift_task_suspend",
            "_swift_task_resume",
            "_swift_task_future_wait",
            "_swift_task_future_create",
            "_swift_task_detach",
            "_swift_task_group_create",
            "_swift_task_group_add",
            "_swift_task_group_wait",
            "_swift_task_isCancelled"
        );

        // Bridging and Objective-C
        addCategory("Bridging",
            "_swift_bridgeObjectRetain",
            "_swift_bridgeObjectRelease",
            "_swift_bridgeFromObjectiveC",
            "_swift_bridgeToObjectiveC",
            "_swift_objc_getClass",
            "_swift_objc_getProtocol",
            "_swift_objc_getSelector",
            "_swift_objc_allocateClassPair",
            "_swift_objc_registerClassPair",
            "_swift_objc_autorelease"
        );

        // Type Metadata
        addCategory("Type Metadata",
            "_swift_getClass",
            "_swift_getTypeByMangledName",
            "_swift_getTypeByMangledNameInContext",
            "_swift_getTypeMetadata",
            "_swift_getTypeMetadata2",
            "_swift_getTypeMetadata3",
            "_swift_getSuperclass",
            "_swift_getSuperclassTypeMetadata",
            "_swift_getWitnessTable",
            "_swift_getGenericWitnessTable",
            "_swift_getAssociatedTypeWitness"
        );

        // Reflection
        addCategory("Reflection",
            "_swift_reflectionMirror_create",
            "_swift_reflectionMirror_destroy",
            "_swift_reflectionMetadataForClass",
            "_swift_reflectionMetadataForObject"
        );

        // Error Handling
        addCategory("Error Handling",
            "_swift_getErrorType",
            "_swift_getErrorMetadata",
            "_swift_errorRetain",
            "_swift_errorRelease",
            "_swift_isError",
            "_swift_errorThrow",
            "_swift_errorCatch"
        );

        // Protocol and Witness Tables
        addCategory("Protocol",
            "_swift_getProtocolConformance",
            "_swift_getWitnessTable",
            "_swift_getGenericWitnessTable",
            "_swift_getAssociatedTypeWitness",
            "_swift_protocolRequiresWitnessTable"
        );

        // KeyPaths
        addCategory("KeyPaths",
            "_swift_keyPathRetain",
            "_swift_keyPathRelease",
            "_swift_keyPathAllocate",
            "_swift_keyPathCopy",
            "_swift_keyPathCreate"
        );

        // Atomic Operations
        addCategory("Atomic",
            "_swift_atomicLoad",
            "_swift_atomicStore",
            "_swift_atomicCompareExchange",
            "_swift_atomicFetchAdd",
            "_swift_atomicFetchSub"
        );

        // Miscellaneous
        addCategory("Miscellaneous",
            "_swift_once",
            "_swift_conformsToProtocol",
            "_swift_objectForKey",
            "_swift_setObjectForKey",
            "_swift_getAssociatedObject",
            "_swift_setAssociatedObject",
            "_swift_deallocateAssociatedObject",
            "_swift_getEnclosingContext",
            "_swift_currentContext",
            "_swift_getFieldAt"
        );

        // Objective-C Memory Management
        addCategory("Objective-C Memory",
            "_objc_retain",
            "_objc_release",
            "_objc_retainAutoreleasedReturnValue",
            "_objc_retainAutorelease",
            "_objc_storeStrong",
            "_objc_loadWeak",
            "_objc_storeWeak",
            "_objc_copyWeak",
            "_objc_destroyWeak",
            "_objc_clearDeallocating",
            "_objc_autorelease",
            "_objc_autoreleasePoolPush",
            "_objc_autoreleasePoolPop",
            "_objc_autoreleaseReturnValue"
        );

        // Objective-C Dynamic Messaging
        addCategory("Objective-C Messaging",
            "_objc_msgSend",
            "_objc_msgSendSuper",
            "_objc_msgSendSuper2",
            "_objc_msgSend_stret",
            "_objc_msgSend_fpret",
            "_objc_msgLookup",
            "_objc_msgForward",
            "_objc_msgForward_stret",
            "_objc_msgSendUncached"
        );

        // Objective-C Class and Metaclass
        addCategory("Objective-C Class",
            "_objc_getClass",
            "_objc_getMetaClass",
            "_objc_getRequiredClass",
            "_objc_getClassList",
            "_objc_registerClassPair",
            "_objc_setFutureClass",
            "_objc_allocateClassPair",
            "_objc_disposeClassPair",
            "_objc_duplicateClass",
            "_objc_copyClassNamesForImage",
            "_objc_setHook_getClass",
            "_objc_setHook_getMetaClass"
        );

        // Objective-C Property and KVC
        addCategory("Objective-C Property",
            "_objc_copyPropertyList",
            "_objc_getProperty",
            "_objc_setProperty",
            "_objc_copyPropertyAttributes",
            "_objc_setKey",
            "_objc_getKey",
            "_objc_getKeyPath",
            "_objc_setKeyPath"
        );

        // Objective-C Protocol
        addCategory("Objective-C Protocol",
            "_objc_getProtocol",
            "_objc_registerProtocol",
            "_objc_conformsToProtocol",
            "_objc_allocateProtocol",
            "_objc_addProtocol",
            "_objc_setProtocolMethodTypes",
            "_objc_getSelector",
            "_objc_selector_register"
        );

        // Objective-C Exception Handling
        addCategory("Objective-C Exceptions",
            "_objc_terminate",
            "_objc_begin_catch",
            "_objc_end_catch",
            "_objc_exception_throw",
            "_objc_setExceptionPreprocessor",
            "_objc_setExceptionHandler"
        );

        // Objective-C Associated Objects
        addCategory("Objective-C Associated",
            "_objc_setAssociatedObject",
            "_objc_getAssociatedObject",
            "_objc_removeAssociatedObjects"
        );

        // Objective-C Block Operations
        addCategory("Objective-C Blocks",
            "_objc_block_copy",
            "_objc_block_release",
            "_objc_block_store"
        );

        // Objective-C Synchronization
        addCategory("Objective-C Sync",
            "_objc_sync_enter",
            "_objc_sync_exit",
            "_objc_initialize",
            "_objc_initializeClassPair",
            "_objc_fixupClassPair",
            "_objc_demangleClassName"
        );
    }

    private static void addCategory(String category, String... methods) {
        Set<String> methodSet = new HashSet<>();
        for (String method : methods) {
            methodSet.add(method);
        }
        methodCategories.put(category, methodSet);
    }

    public static Set<String> getMethodsInCategory(String category) {
        return methodCategories.getOrDefault(category, new HashSet<>());
    }

    public static Set<String> getAllMethods() {
        Set<String> allMethods = new HashSet<>();
        methodCategories.values().forEach(allMethods::addAll);
        return allMethods;
    }

    public static String getCategoryForMethod(String method) {
        for (Map.Entry<String, Set<String>> entry : methodCategories.entrySet()) {
            if (entry.getValue().contains(method)) {
                return entry.getKey();
            }
        }
        return "Unknown";
    }

    public static Set<String> getCategories() {
        return methodCategories.keySet();
    }

    public static boolean isSwiftRuntimeMethod(String method) {
        return getAllMethods().contains(method);
    }
} 