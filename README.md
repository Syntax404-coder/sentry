Here is a comprehensive, professional `README.md` file for the Sentry project. It is formatted using standard Markdown syntax suitable for GitHub, GitLab, or Azure DevOps.

-----

# Sentry: Advanced Process Monitoring & System Activity Tracker

**Sentry** is a high-performance Command-Line Interface (CLI) utility designed for power users, system administrators, and developers. Built entirely within the PowerShell environment, it bridges the gap between standard monitoring tools (like Task Manager) and kernel-level system manipulation.

Sentry provides granular control over running applications, including the ability to suspend execution threads, latch processes to specific CPU cores, and surgically remove startup applications from the Windows Registry.

## Table of Contents

1.  [Overview](https://www.google.com/search?q=%23overview)
2.  [Key Features](https://www.google.com/search?q=%23key-features)
3.  [System Requirements](https://www.google.com/search?q=%23system-requirements)
4.  [Installation](https://www.google.com/search?q=%23installation)
5.  [Usage Guide](https://www.google.com/search?q=%23usage-guide)
      * [Main Menu](https://www.google.com/search?q=%23main-menu)
      * [Deep Process Control](https://www.google.com/search?q=%23deep-process-control)
      * [Startup Manager](https://www.google.com/search?q=%23startup-manager)
6.  [Technical Architecture](https://www.google.com/search?q=%23technical-architecture)
7.  [Disclaimer](https://www.google.com/search?q=%23disclaimer)
8.  [License](https://www.google.com/search?q=%23license)

-----

## Overview

Modern operating systems often prioritize safety and user-friendliness over granular control. When a system is under heavy load or an application becomes unresponsive, graphical interfaces can be slow to launch. Sentry leverages the speed of the command console and the power of the .NET framework to provide an instant, lightweight dashboard for system management.

Unlike standard tools, Sentry allows for "God Mode" capabilities, utilizing C\# method injection to access Windows API calls not natively exposed in PowerShell.

## Key Features

### 1\. Deep Process Control

Beyond simple termination, Sentry offers advanced management for running tasks:

  * **Tree Kill:** Forcefully terminates a parent process and all child sub-processes (e.g., closing all browser tabs instantly).
  * **Freeze / Resume:** Uses `ntdll.dll` to suspend process threads in memory, allowing users to pause resource-heavy applications without closing them.
  * **CPU Affinity:** Latch specific processes to physical CPU cores.
  * **Priority Management:** Dynamically adjust process priority classes (Idle, Normal, High, RealTime).

### 2\. Startup Optimization

  * **BIOS Boot Analysis:** Retrieves the exact "Last BIOS Boot Time" (in seconds) from the Windows Event Log.
  * **Registry Management:** Scans `HKCU` and `HKLM` run keys and allows for the permanent deletion of startup entries to reduce boot latency.

### 3\. Security & Heuristics

  * **Shady Process Scanner:** Uses behavioral heuristics to flag potentially malicious processes based on unsigned code, suspicious file paths (AppData/Temp), and hidden window states.
  * **Network Sentinel:** Filters active TCP/UDP connections to identify applications establishing external communication.

### 4\. Intelligence & Logging

  * **Activity Logger:** Snapshots active processes to a local JSON database.
  * **Usage Intelligence:** Calculates average session durations and identifies the most frequently used applications over time.
  * **Live Dashboard:** A secondary "Heads-Up Display" for real-time monitoring on separate screens.

-----

## System Requirements

  * **Operating System:** Windows 10 or Windows 11 (64-bit).
  * **Environment:** Windows PowerShell 5.1 or PowerShell Core 7+.
  * **Permissions:** Administrative privileges are **mandatory** for Registry access and process suspension.

## Installation

Sentry is a portable, single-file application. No installation wizard is required.

1.  **Download:**
    Download the `Sentry.ps1` file to a local directory (e.g., `C:\Tools\Sentry`).

2.  **Unblock File:**
    Windows may block scripts downloaded from the internet. Run the following command in PowerShell:

    ```powershell
    Unblock-File -Path C:\Tools\Sentry\Sentry.ps1
    ```

3.  **Execution Policy:**
    Ensure your system allows script execution. Run PowerShell as Administrator and execute:

    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    ```

-----

## Usage Guide

To launch the application, open PowerShell as **Administrator** and run:

```powershell
.\Sentry.ps1
```

### Main Menu

The dashboard is navigable using numeric keys `0-9`.

  * **[ 1 ] View Top Memory Hogs:** Displays top 30 processes sorted by Working Set (RAM). Supports pagination.
  * **[ 2 ] View Top CPU Hogs:** Displays top 30 processes sorted by Processor Time.
  * **[ 3 ] Startup Apps Manager:** Manage boot applications and registry keys.
  * **[ 4 ] Active Traffic Scanner:** View established network connections.
  * **[ 5 ] Shady Process Scanner:** Run security heuristics.
  * **[ 6 ] Manage Process:** Access the deep control sub-menu.
  * **[ 7-9 ] Logging & HUD:** Access historical data and real-time dashboards.
  * **[ 0 ] Export Report:** Generate a system status text file.

### Deep Process Control (Option 6)

This module allows for aggressive process management.

1.  **Select View Mode:** Choose between "Safe Mode" (User apps only) or "God Mode" (All system processes).
2.  **Select Target:** Enter the Process ID (PID) or the Application Name.
3.  **Execute Action:**
      * **Kill:** Initiates a Tree Kill command. Requires confirmation.
      * **Freeze:** Calls `NtSuspendProcess`. The app will remain in RAM but consume 0% CPU.
      * **Affinity:** Accepts a comma-separated list of cores (e.g., `0,1,2`).

### Startup Manager (Option 3)

1.  Sentry displays the last BIOS boot time.
2.  It lists all applications found in the Registry Run keys.
3.  Select an item by number to permanently delete the registry key. **This action cannot be undone via the tool.**

-----

## Technical Architecture

Sentry utilizes a hybrid architecture combining PowerShell scripting with .NET Framework integration.

  * **P/Invoke (Platform Invocation):**
    To achieve functionality not natively available in PowerShell cmdlets, Sentry compiles C\# code at runtime using `Add-Type`. This allows direct access to the `ntdll.dll` library for memory handle manipulation.

  * **Data Persistence:**
    Activity logs are stored in standard JSON format (`sentry_activity_log.json`) within the script's root directory. To maintain performance, the log file automatically trims itself to the most recent 5,000 entries.

  * **Visual Rendering:**
    The user interface relies on ANSI escape codes for high-contrast coloring and ASCII block characters for rendering bar charts, ensuring compatibility with standard Windows terminals (conhost) and Windows Terminal.

-----

## Disclaimer

**Use with caution.**

Sentry provides administrative access to critical system functions.

  * **Process Termination:** Forcing the termination of system-critical processes (e.g., `csrss.exe`, `wininit.exe`) will result in a Blue Screen of Death (BSOD) and immediate system restart.
  * **Registry Editing:** The Startup Manager permanently deletes registry keys. Ensure you are deleting the correct application entry.

The authors and contributors are not responsible for any data loss, system instability, or hardware damage resulting from the misuse of this tool.

-----

## License

This project is open-source and available for modification and distribution. Refer to the `LICENSE` file in the repository for specific terms.
