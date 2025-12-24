# Develop EDR Using TDD

![Platform](https://img.shields.io/badge/platform-Windows-0078D6) ![Language](https://img.shields.io/badge/language-C%2B%2B-blue) ![Standard](https://img.shields.io/badge/standard-C%2B%2B17%2F20-blue)

**Develop EDR Using TDD** is a custom Endpoint Detection and Response (EDR) agent built for Windows. It leverages **Event Tracing for Windows (ETW)** for real-time telemetry and integrates **YARA-X** for signature-based malware detection.

The project focuses on detecting specific malware behaviors using a unified scanning logic that correlates registry, file, and process activities.

## ✨ Features

* **Real-time Kernel Telemetry:** Uses [KrabsETW](https://github.com/microsoft/krabsetw) to consume ETW events for processes, image loads, registry operations, and file IO.
* **Behavioral Correlation:** Aggregates multiple suspicious actions (Registry + File + Process Access) to reduce false positives before triggering an alert.
* **Signature Scanning:** Integrated [YARA-X](https://github.com/VirusTotal/yara-x) engine to scan process memory and files against embedded rules.
* **Specific Detection Capabilities:**
    * **Registry:** Detects suspicious persistence keys (e.g., `Software\BOMBE`).
    * **File Access:** Monitors attempts to access sensitive data (e.g., Chrome's `Login Data`).
    * **Process Protection:** Detects unauthorized handle access to protected processes (e.g., `bsass.exe`).

## 🛠 Prerequisites

Before building the project, ensure you have the following installed:
* **Windows 10/11** (x64 recommended)
* **Visual Studio 2022** (v17.x) with C++ Desktop Development workload.
* **Administrative Privileges** (Required to run the agent and consume ETW).

## ⚙️ Installation & Setup

This project relies on external libraries that must be placed in a specific directory structure.

### 1. Library Setup (Critical)
You must create a `Library` folder in your `C:` drive and populate it with the required dependencies:

1. Create the directory: `C:\Library`
2. Download and extract **KrabsETW** and **YARA-X** into this folder.
3. After extract YARA-X, use Rust to compile it.
```
cargo build -p yara-x-capi --release
```

Your directory structure **must** look like this for the solution to link correctly:

```text
C:\
└── Library\
    ├── krabsetw-master\       
    └── yara-x\          
```

### 2. Clone the Repository
```bash
git clone [https://github.com/yourusername/Develop-EDR-Using-TDD.git](https://github.com/yourusername/Develop-EDR-Using-TDD.git)
cd Develop-EDR-Using-TDD
```

### 3. Build the Project
- Open EDR-Development-via-TDD.sln in Visual Studio.
- Set the build configuration to Debug or Release (x64 is recommended).
- Build the Solution.

## 📂 Project Structure
EDR_Agent/: Main entry point. Handles ETW callbacks and orchestrates scanning.

`Detectors/`:
- RegistryDetector.h: Analyzes registry key modifications.
- FileDetector.cpp: Analyzes file IO operations.
- ProcessAccessDetector.h: Monitors OpenProcess calls against victim processes.

`Scanning Engine/`:
- MalwareScanner.cpp: Wrapper for YARA-X to scan files and memory.
- EmbeddedRules.h: Contains the compiled YARA rulesets.

`Core Logic/`:
- BehaviorTracker.h: Tracks "strikes" against a PID to determine if it is malicious.

## Usage
Navigate to the output directory (e.g., x64/Debug).

Run as Administrator:
```cmd
EDR_Agent.exe
```
The agent will initialize ETW sessions (MyEDR_Kernel_Trace and MyEDR_Api_Trace) and begin monitoring.
