package com.lauriewired.malimite.configuration;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Collections;
import java.util.ArrayList;

public class LibraryDefinitions {
    // Common iOS frameworks to avoid decompiling
    private static final List<String> DEFAULT_LIBRARIES = Arrays.asList(
        "UIKit",
        "Foundation",
        "CoreData",
        "CoreGraphics",
        "CoreLocation",
        "AVFoundation",
        "WebKit",
        "Security",
        "NetworkExtension",
        "SystemConfiguration",
        "CoreBluetooth",
        "CoreMotion",
        "Photos",
        "Contacts",
        "HealthKit",
        "HomeKit",
        "MapKit",
        "MessageUI",
        "StoreKit",
        "UserNotifications",
        "SwiftStandardLibrary",
        "SwiftUI",
        "Combine",
        "CoreFoundation",
        "QuartzCore",
        "CFNetwork",
        "CoreImage",
        "Metal",
        "SceneKit",
        "ARKit",
        "SpriteKit",
        "GameKit",
        "BackgroundTasks",
        "CloudKit",
        "FileProvider",
        "CoreText",
        "Vision",
        "TextKit",
        "CoreML",
        "NaturalLanguage",
        "AppTrackingTransparency",
        "AuthenticationServices",
        "Intents",
        "CallKit",
        "MediaPlayer",
        "PassKit"
    );
    

    public static List<String> getDefaultLibraries() {
        return DEFAULT_LIBRARIES;
    }

    public static List<String> getActiveLibraries(Config config) {
        Set<String> activeLibraries = new HashSet<>(DEFAULT_LIBRARIES);
        
        // Remove any libraries that the user has explicitly removed
        activeLibraries.removeAll(config.getRemovedLibraries());
        
        // Add any custom libraries the user has added
        activeLibraries.addAll(config.getAddedLibraries());
        
        // Convert back to sorted list for consistent ordering
        List<String> sortedLibraries = new ArrayList<>(activeLibraries);
        Collections.sort(sortedLibraries);
        return sortedLibraries;
    }
} 