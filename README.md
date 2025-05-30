<h5>Readme - asd-windows-hardening -  Version 1.1</h5> 

# asd-windows-hardening
A PowerShell script that implements the Australian Signals Directorate (ASD) Windows hardening recommendations along with integrated Microsoft Security Baseline deployment. 
This tool enhances Windows security and privacy through automated configuration of hundreds of security settings.

<h2>🚀 Features: </h2>

🔒 Microsoft Security Baseline Integration - Auto-detects and applies official Microsoft security baselines

🛡️ ASD Security Hardening - Complete implementation of ASD hardening recommendations

🔐 Privacy Protection - Comprehensive telemetry and tracking disabling

📝 Detailed Logging - Full audit trail of all changes with timestamps

↩️ Backup Creation - Registry backups for rollback capability

🔍 Smart Detection - Automatic baseline file detection and compatibility checking

🎯 Multiple Modes - Interactive wizard, automated execution, or dry-run preview

<h2>📋 Requirements: </h2>

<li>Windows 10 (version 2004+) or Windows 11 </li>
<li>PowerShell 5.1 or later </li>
<li>Administrator privileges </li>
<li>Microsoft Security Baseline files (optional, for baseline installation)</li>

<h2>📥 Installation: </h2>

<h4>Method 1: Download from GitHub</h4>

<li>Download the latest release from the Releases page </li>
<li>Extract the ZIP file to your preferred location </li>
<li>Right-click on PowerShell and select "Run as Administrator"</li>
<li>Navigate to the extracted folder </li>

<h4>Method 2: Clone Repository </h4>

```powershell:
git clone https://github.com/BenuBurk/asd-windows-hardening.git
cd asd-windows-hardening
```
<h4>Method 3: Direct Download </h4>

```powershell
# Download the script directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/BenuBurk/asd-windows-hardening/main/enhanced_asd_hardening.ps1" -OutFile "enhanced_asd_hardening.ps1"
```
<h2>🔧 Usage </h2>

<h4>Interactive Mode (Recommended) </h4>

```powershell
# Run the interactive wizard
.\enhanced_asd_hardening.ps1
```
<h4>Automated Execution</h4>

```powershell
# Apply only Microsoft Security Baseline
.\enhanced_asd_hardening.ps1 -Mode Baseline -Force

# Apply only ASD hardening rules
.\enhanced_asd_hardening.ps1 -Mode Hardening -Force

# Apply everything (baseline + hardening)
.\enhanced_asd_hardening.ps1 -Mode All -Force

# Preview changes without applying (dry run)
.\enhanced_asd_hardening.ps1 -DryRun

# Specify custom baseline location
.\enhanced_asd_hardening.ps1 -Mode Baseline -BaselinePath "C:\Downloads\Windows-11-Security-Baseline"
```

<h4>Command Line Parameters</h4>

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Mode` | Execution mode: `Interactive`, `Baseline`, `Hardening`, `All` | `Interactive` |
| `-Force` | Skip confirmation prompts | `False` |
| `-DryRun` | Preview changes without applying them | `False` |
| `-BaselinePath` | Custom path to baseline files | Auto-detect |
| `-LogPath` | Custom log file location | `%TEMP%\ASD_Hardening_[timestamp].log` |



<h2>📦 Microsoft Security Baseline Setup </h2>
To use the baseline functionality:

<h4>1. Download the required files:</h4>

<li>Visit: https://www.microsoft.com/en-us/download/details.aspx?id=55319 </li>
<li>Download both baseline matching your Windows version and LGPO.zip </li>
<li>Example: "Windows 11 version 24H2 Security Baseline" </li>


<h4>2. Extract both files: </h4>

<li>Extract both ZIP files to the Downloads folder </li>
<li>Place the LGPO.exe file that you find in the extracted LGPO* folder (e.g. LGPO30) in the extracted Baseline folder under "Scripts", e.g. "Windows 11 v24H2 Security Baseline\Scripts\<b>place LGPO.exe here"</b> </li>
<li>Ensure the folder structure contains Scripts\LGPO.exe, e.g "Windows 11 v24H2 Security Baseline\Scripts\LGPO.exe"</li>


<h4>3. Run the script: </h4>

<li>The script will automatically detect baseline files in common locations </li>
<li>Or specify the path with -BaselinePath parameter</li>



<h2>🛡️ Security Features Applied</h2>
<h4>Microsoft Security Baseline</h4>

<li>Hundreds of security settings as recommended by Microsoft</li>
<li>Authentication policies and credential protection</li>
<li>Network security configurations</li>
<li>Application security controls</li>
<li>Audit and logging enhancements</li>

<h4>ASD Security Hardening</h4>


<li>Attack Surface Reduction: 16 ASR rules to block common attack vectors</li>
<li>Credential Guard: Hardware-based credential isolation and LSASS protection</li>
<li>Network Hardening: Disable NetBIOS, LLMNR, and mDNS</li>
<li>Authentication Security: Disable security questions, anonymous access</li>
<li>UAC Enhancement: Maximum security configuration</li>
<li>Remote Access: Harden WinRM, disable Remote Assistance</li>
<li>AutoPlay/AutoRun: Complete disable for malware prevention</li>

<h4>Privacy Protection </h4>

<li>Telemetry Disable: Turn off Windows diagnostic data collection</li>
<li>Location Services: Disable GPS and sensor tracking</li>
<li>Advertising: Remove advertising ID and targeting</li>
<li>Microsoft Accounts: Block cloud account integration</li>
<li>Activity Tracking: Disable Timeline, Find My Device, Wi-Fi Sense</li>
<li>Cloud Features: Disable Edge sync, handwriting personalization</li>
<li>Background Services: Disable telemetry services and scheduled tasks</li>


<h2>📊 Logging and Verification </h2>
<h4>Logging</h4>

<li>All changes are logged with timestamps</li>
<li>Separate log levels: INFO, SUCCESS, WARN, ERROR</li>
<li>Registry backups created before modifications</li>
<li>Log location: %TEMP%\ASD_Hardening_[timestamp].log</li>

<h2>Verification</h2>

The script does not perform baseline verification due to complexity (hundreds of settings). 

Instead, use Microsoft's official tools:

<li>Security Compliance Toolkit (SCT) </li>
<li>Policy Analyzer</li>
<li>Microsoft Security Baseline Analyzer</li>

Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319

<h2>⚠️ Important Warnings </h2>

<h4>Before Running !!! </h4>

<li><b>TEST IN A VM FIRST - Always test on a non-production system</b></li>
<li>Create System Backup - Full system backup recommended</li>
<li>Review Settings - Understand what will be changed</li>
<li>Check Compatibility - Ensure baseline matches your Windows version</li>

<h4>Potential Impact</h4>

<li>Some Windows features may be disabled (Cortana, location services, etc.) </li>
<li>Network discovery and file sharing may be affected</li>
<li>Some apps may require reconfiguration</li>
<li>Remote management capabilities will be restricted</li>

<h2>🔄 Rollback and Recovery </h2>

<h4>Registry Restoration</h4>

```powershell
# Registry backups are created in %TEMP%\Backup_*.reg
# To restore manually:
reg import "C:\Users\[Username]\AppData\Local\Temp\Backup_[KeyName].reg"
```
<h4>Service Restoration</h4>

```powershell
# Re-enable disabled services if needed:
Set-Service -Name "ServiceName" -StartupType Automatic
Start-Service -Name "ServiceName"
```

<h2>⚠️ Disclaimer </h2>
This script modifies critical system settings. While based on official Microsoft and ASD recommendations, the authors are not responsible for any system issues or data loss. Always test in a non-production environment first.

<h2>🔗 References </h2>

<li><a href="https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/hardening-microsoft-windows-10-version-21h1-workstations">ASD Windows Hardening Guidelines</a></li>
<li><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines">Microsoft Security Baselines</a></li>

<h2>📄 License </h2>

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
