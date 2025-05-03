# 🛡️ PowerShell Detection & SOAR Response

This project detects suspicious PowerShell activity such as obfuscation or script downloading behavior. The detection logic is written in Splunk SPL, and a Python script is included to simulate a response (e.g., blocking the source IP).

---

## 🔍 Detection Logic

The SPL query monitors Windows logs for behaviors like:
- Base64-encoded commands
- Use of `Invoke-Mimikatz`
- Use of `iex` (Invoke-Expression)
- External script execution via `WebClient.DownloadString`

```spl
index=windows EventCode=4104 OR EventCode=4688
| eval PowershellCommand=coalesce(ScriptBlockText, CommandLine)
| where like(PowershellCommand, "%Invoke-Mimikatz%") 
    OR like(PowershellCommand, "%FromBase64String%") 
    OR like(PowershellCommand, "%iex%")
| stats count by _time, host, user, PowershellCommand
