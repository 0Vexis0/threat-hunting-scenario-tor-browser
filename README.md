# threat-hunting-scenario-tor-browser

# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/0Vexis0/threat-hunting-scenario-tor-browser/blob/main/Scenario%20creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "cybernecromancy"  
| where InitiatingProcessAccountName == "cybermaster"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1372" height="369" alt="image" src="https://github.com/user-attachments/assets/b444a867-defc-495e-914e-aae11571c6ba" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "cybernecromancy"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, DeviceName, FileName, AccountName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1358" height="102" alt="image" src="https://github.com/user-attachments/assets/4c791310-63f5-40ba-b284-4e5a65e1df36" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "cybernecromancy"
| where FileName has_any ("tor.exe", "firefox", "tor-browser.exe")
| project Timestamp, DeviceName, FileName, AccountName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```

<img width="1828" height="760" alt="image" src="https://github.com/user-attachments/assets/cc06d3e8-04ab-43d7-ad6d-2d1317e4e6ec" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "cybernecromancy"
| where InitiatingProcessAccountName != "SYSTEM"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```

<img width="1886" height="329" alt="image" src="https://github.com/user-attachments/assets/a7eed906-76d4-4318-b390-43742a25a070" />

---

Chronological Events


TOR Browser Threat Hunt Timeline (Chronological)
2025-12-24 21:03:55.2601082 UTC
Initial TOR-related file activity detected
DeviceFileEvents logs show the first TOR-related artifacts appearing on the system.


Files containing the string “tor” were written to disk.


Activity attributed to account cybermaster.


Evidence indicates:


A TOR installer was downloaded.


Multiple TOR-related files were copied to the Desktop.


Creation of a text file named tor-shopping-list.txt.


This marks the earliest observable indicator of TOR-related activity on the host.


Significance:
 This represents the initial compromise vector or policy-violating software introduction phase.

2025-12-24 21:11:54.147233 UTC
TOR Browser installation executed
DeviceProcessEvents confirm execution of:


tor-browser-windows-x86_64-portable-15.0.3.exe


Executed from the Downloads directory.


The command line indicates a silent installation, suggesting user intent to deploy TOR without interactive prompts.


Significance:
 Confirms intentional installation of TOR Browser rather than passive file presence.

2025-12-24 21:13:25 UTC
TOR Browser first execution
DeviceProcessEvents show firefox.exe and tor.exe processes spawning from the TOR Browser directory.


This timestamp confirms the first known execution of the TOR Browser application.


Additional TOR-related processes were spawned shortly afterward.


Significance:
 This is the transition point from installation to active usage.

2025-12-24 21:14:18.2498868 UTC
TOR network communication initiated (Port 9150 / related ports)
DeviceNetworkEvents logs show outbound connections on known TOR ports.


Initiating process was not SYSTEM, indicating user-launched activity.


TOR-associated ports observed include:


9150


9050 / 9051 (loopback and SOCKS proxy usage typical of TOR)


Significance:
 Confirms successful TOR circuit establishment.

2025-12-24 21:15:32.6853456 UTC
Continued TOR network activity
Additional outbound TOR connections observed.


Indicates persistence of TOR Browser session.



2025-12-24 21:16:11.7999242 UTC
Ongoing TOR network usage
Further TOR-related outbound traffic detected.


Confirms sustained TOR usage rather than a single test launch.


Significance:
 Establishes active anonymized browsing behavior.

---

## Summary

On December 24, the computer named cybernecromancy showed clear signs that a special privacy-focused web browser called Tor was deliberately downloaded and used. First, files related to Tor appeared on the system, including an installer and a text file that suggested the user was actively working with the program. Shortly after, the Tor installer was run, which placed the browser on the computer without requiring much user interaction. The browser was then opened, confirming it was not just downloaded but actually used. Once opened, the browser created multiple background programs that are normal for Tor. The computer then began making internet connections through known Tor pathways, which are designed to hide a user’s online activity. These connections continued for several minutes, showing sustained use rather than a brief test. Overall, the evidence shows that Tor was intentionally installed and used on this computer to browse the internet in a more anonymous way.

---

## Response Taken

TOR usage was confirmed on the endpoint `cybernecromancy` by the user `cybermaster`. The device was isolated, and the user's direct manager was notified.

---
