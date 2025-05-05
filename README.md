
-

#  PowerShell Obfuscation Detection & Automated Response

In this lab, I focused on detecting suspicious use of PowerShell in Windows environments. PowerShell is commonly abused by attackers to execute encoded or obfuscated commands in memory, often avoiding detection by antivirus tools. Techniques like `iex`, base64 strings, and `DownloadString` are frequently seen in red team and real-world threats.

###  Objective

Create a detection in Splunk to identify suspicious PowerShell behavior and respond automatically using a Python-based SOAR simulation.

###  Attack Simulation

To simulate this:
- I ran an encoded PowerShell command (`-encodedCommand`)
- I tested `iex` and `New-Object Net.WebClient` to simulate script downloads

These behaviors align with:
- **T1059.001 – PowerShell (Execution)**
- **T1027 – Obfuscated Files or Information (Defense Evasion)**
- **T1105 – Ingress Tool Transfer (C2)**

### Detection Logic (SPL)

The following query was built to catch malicious PowerShell activity based on ScriptBlock Logging and Process Creation logs:



