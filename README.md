![Malimite logo](https://github.com/LaurieWired/Malimite/blob/main/media/malimite_logo.png)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/Malimite)](https://github.com/LaurieWired/Malimite/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/Malimite)](https://github.com/LaurieWired/Malimite/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/Malimite)](https://github.com/LaurieWired/Malimite/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/Malimite)](https://github.com/LaurieWired/Malimite/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

# Description

Malimite is an iOS and macOS decompiler designed to help researchers analyze and decode IPA files and Application Bundles.

Built on top of Ghidra decompilation to offer direct support for Swift, Objective-C, and Apple resources.

![Malimite Features](https://github.com/LaurieWired/Malimite/blob/main/media/malimite_features_github.png)

# Features

- Multi-Platform
  - Mac, Windows, Linux
- Direct support for IPA and bundle files
- Auto decodes iOS resources
- Avoids lib code decompilation
- Reconstructs Swift classes
- **Built-in LLM method translation**

---

# Project Architecture

## Directory Structure

| Directory                                 | Description                           |
| ----------------------------------------- | ------------------------------------- |
| `src/main/java/com/lauriewired/malimite/` | Main Java source code                 |
| `DecompilerBridge/ghidra/`                | Ghidra integration script             |
| `src/main/antlr4/`                        | ANTLR4 grammar files for C++14 parser |
| `media/`                                  | Logo and images                       |
| `Casks/`                                  | Homebrew Cask formula                 |

## Core Components

### Main Application

- **Malimite.java** - Entry point, Swing-based GUI with FlatLaf theming (dark/light mode)
- Drag & drop file selection
- Recent projects list

### Decompilation Engine

| File                    | Purpose                                                   |
| ----------------------- | --------------------------------------------------------- |
| `GhidraProject.java`    | Decompiles Mach-O files using Ghidra headless analyzer    |
| `DynamicDecompile.java` | On-demand decompilation                                   |
| `DumpClassData.java`    | Ghidra script - extracts class, function, and string data |
| `DemangleSwift.java`    | Demangles Swift symbol names                              |
| `SyntaxParser.java`     | Syntax analysis using CPP14 ANTLR parser                  |

### File Processing

| File                   | Purpose                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| `Macho.java`           | Mach-O binary parser (Universal binary support, architecture selection) |
| `InfoPlist.java`       | Info.plist reading and parsing                                          |
| `MobileProvision.java` | Mobile provisioning profile reading                                     |

### Database

- **SQLiteDBHandler.java** - Stores project data in SQLite
  - Classes, functions, decompiled code, strings, references

### Configuration

| File                      | Purpose                                          |
| ------------------------- | ------------------------------------------------ |
| `Config.java`             | Ghidra path, theme, API keys, project paths      |
| `Project.java`            | Project state and metadata                       |
| `LibraryDefinitions.java` | Library definitions to skip during decompilation |

### AI Integration

- **AIBackend.java** - LLM integration for code analysis
  - OpenAI GPT-4 support
  - Claude (Anthropic) support
  - Local LLM support (e.g., LM Studio)

### UI Components

| File                       | Purpose                    |
| -------------------------- | -------------------------- |
| `AnalysisWindow.java`      | Main analysis window       |
| `PreferencesDialog.java`   | Settings dialog            |
| `SearchResultsDialog.java` | Search results             |
| `ReferencesDialog.java`    | Function references viewer |
| `SyntaxHighlighter.java`   | Code syntax highlighting   |

---

# Technology Stack

| Technology          | Purpose                                    |
| ------------------- | ------------------------------------------ |
| **Java 11**         | Main language                              |
| **Maven**           | Build system                               |
| **Ghidra**          | Decompilation engine (external dependency) |
| **ANTLR4**          | C++14 parsing                              |
| **SQLite**          | Database                                   |
| **FlatLaf**         | Modern Swing theme                         |
| **RSyntaxTextArea** | Code editor component                      |
| **Bouncy Castle**   | Encryption (for API keys)                  |
| **dd-plist**        | Plist file parsing                         |
| **Flexmark**        | Markdown rendering                         |

---

# Workflow

```
1. Select IPA/Bundle file
       ↓
2. Unzip file (if IPA)
       ↓
3. Find Mach-O binary (select architecture if Universal)
       ↓
4. Run Ghidra headless analyzer
       ↓
5. Execute DumpClassData.java script
       ↓
6. Receive class/function data + decompiled code
       ↓
7. Store in SQLite database
       ↓
8. Display in tree view
       ↓
9. (Optional) Analyze with AI
```

---

# Key Capabilities

1. **Library Filtering**: Apple frameworks are automatically skipped during decompilation via `LibraryDefinitions.java`
2. **Swift Support**: Detects `__swift5` segment for Swift identification
3. **Universal Binary**: Prompts user for architecture selection when multiple are available
4. **Reference Tracking**: Analyzes cross-function calls
5. **Secure API Key Storage**: Encryption via Bouncy Castle

---

# Privacy & Security

**Everything runs LOCAL!** Your IPA files are never sent to external servers.

## Fully Local Components

| Component                 | Status                                     |
| ------------------------- | ------------------------------------------ |
| **Ghidra Decompiler**     | ✅ LOCAL - Runs on your machine            |
| **SQLite Database**       | ✅ LOCAL - `.db` file in project folder    |
| **IPA/Bundle Processing** | ✅ LOCAL - Files never leave your computer |
| **UI (Swing)**            | ✅ LOCAL - Desktop application             |

## AI Features (Optional)

If you use AI code analysis:

| AI Option                       | Network                     |
| ------------------------------- | --------------------------- |
| **OpenAI GPT-4**                | 🌐 Sends to OpenAI API      |
| **Claude**                      | 🌐 Sends to Anthropic API   |
| **Local LLM** (LM Studio, etc.) | ✅ LOCAL - `localhost:1234` |

> 💡 **If you don't use AI features, no data is sent to the internet!**

## Project Data Location

When you analyze an IPA, a project folder is created next to it:

```
/path/to/MyApp.ipa
/path/to/MyApp_malimite/
    ├── project.json      # Project settings
    ├── database.db       # SQLite database
    └── extracted/        # Extracted files
```

---

# Installation

A precompiled JAR file is provided in the [Releases Page](https://github.com/LaurieWired/Malimite/releases/)

For full Installation steps consult the Wiki.

---

# Quick Start

### 1. Prerequisites

- **Java 11+** must be installed
- **Ghidra** must be installed - Download from [ghidra-sre.org](https://ghidra-sre.org/)
- **Maven** (only for building from source)

### 2. Build the Project

```bash
cd /path/to/Malimite
mvn clean package
```

### 3. Run the JAR

```bash
java -jar target/malimite-1.0-SNAPSHOT.jar
```

### 4. First Launch

1. Go to **Preferences** menu and set the Ghidra path (e.g., `/Applications/ghidra_11.0`)
2. Click "**Select File**" and choose your IPA file
3. Click "**Analyze File**" button

### 5. macOS Gatekeeper Fix (if needed)

If you see security warnings about Ghidra components:

```bash
xattr -r -d com.apple.quarantine /path/to/ghidra/
```

---

# Usage + Prerequisites

### Check out the **[Wiki](https://github.com/LaurieWired/Malimite/wiki)** for more details.

# Contribute

- Make a pull request
- Add an Example to our Wiki
- Report an error/issue
- Suggest an improvement
- Share with others or give a star!

Your contributions are greatly appreciated and will help make Malimite an even more powerful and versatile tool for the iOS and macOS Reverse Engineering community.

# License

Malimite is licensed under the Apache 2.0 License. See the [LICENSE](https://www.apache.org/licenses/LICENSE-2.0) file for more information.
