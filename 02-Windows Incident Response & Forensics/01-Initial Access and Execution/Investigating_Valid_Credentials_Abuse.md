# Detection Playbook

## 1. MITRE ATT&CK

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | Adversaries use legitimate credentials to gain unauthorized access to systems or networks. |

Investigation Focus:
- VPN Authentication
- Windows Authentication
- Remote Desktop Protocol (RDP)
- User Profile Initialization


## 2. IMPORTANT DETECTION FILTERS

### A. Windows Security Events

| Event ID | Description | Detection Purpose |
|---|---|---|
| 4624 | Successful Logon | Identify successful authentication |
| 4776 | Credential Validation | Track credential validation |
| 6272 | NPS Access Granted | Identify successful VPN authentication through NPS |

### B. Logon Type

| Logon Type | Description | Relevance |
|---|---|---|
| 3 | Network Logon | VPN / Network Access |
| 10 | RemoteInteractive | RDP Connection |

### C. RDP Event Logs

| Event ID | Description |
|---|---|
| 1149 | Successful RDP Authentication |
| 21 | RDP Session Established |

Log Sources:
- Security.evtx
- rdplocal.evtx


### D. EVTX Fields for IOC Collection

**Event ID 6272 — NPS Access Granted**

| EVTX Field | IOC / Investigation Purpose |
|---|---|
| SubjectUserName | Authenticated username |
| FullyQualifiedSubjectUserName | Fully qualified user identity |
| CallingStationID | Remote source IP address |
| CalledStationID | VPN gateway / target server identifier |
| NASIPv4Address | RADIUS client / VPN device IP |
| NetworkPolicyName | Network policy used to grant access |
| AuthenticationType | Authentication method |

**Event ID 4624 — Successful Logon**

| EVTX Field | IOC / Investigation Purpose |
|---|---|
| TargetUserName | Target account |
| TargetDomainName | Target account domain |
| IpAddress | Source IP address |
| IpPort | Source port |
| WorkstationName | Source workstation |
| LogonType | Authentication type |
| LogonProcessName | Logon process; IAS indicates RADIUS/NPS |
| AuthenticationPackageName | Authentication package (Kerberos/NTLM) |
| LogonGuid | Unique authentication correlation identifier |
| TargetLogonId | Target logon session identifier |

**RDP Event Logs**

| Event ID | Relevant Fields | IOC / Investigation Purpose |
|---|---|---|
| 1149 | User, Domain, Source Network Address | Identify RDP authentication source |
| 21 | User, Session ID | Identify established RDP session |

Note:
The VPN-assigned IP is documented in the TryHackMe NPS text-log section, not as a specifically identified field in Event ID 6272. Do not confuse it with CallingStationID or NASIPv4Address.


## 3. DETECTION PATTERNS

### Pattern 1 — VPN Authentication (RADIUS/NPS)

4776 → 6272 → 4624

- 4776: Credential Validation
- 6272: NPS Access Granted
- 4624: Successful Logon

Correlate using username and timestamps.

### Pattern 2 — Direct LDAP VPN Authentication

VPN Gateway Logs → 4776 → 4624 (Logon Type 3)

Check:
- Public source IP from VPN Gateway Logs.
- Username and timestamp.
- Credential validation.
- Successful network logon.

Note: Event ID 6272 is not generated when NPS/RADIUS
is not involved in the authentication process.

### Pattern 3 — RDP Authentication

4624 (Logon Type 10) + 1149 + 21

- 4624 Type 10: Successful RDP Logon.
- 1149: Successful RDP Authentication.
- 21: RDP Session Established.

Correlate using username, remote IP, timestamp, and session ID.


## 4. REGISTRY FORENSIC INDICATORS

### A. ProfileList

Registry Path:

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList

Inspect:
- User SID
- ProfileImagePath
- Last Write Timestamp

### B. NTUSER.DAT

Location:

C:\Users\<Username>\NTUSER.DAT

PowerShell:

```powershell
Get-Item "C:\Users\<Username>\NTUSER.DAT" -Force |
Select-Object FullName, LastWriteTime, Length
```

Detection Pattern:

4624 Timestamp ≈ ProfileList Last Write Timestamp
4624 Timestamp ≈ NTUSER.DAT LastWriteTime

Use timestamp correlation as supporting evidence,
not as standalone proof of compromise.


## 5. SUSPICIOUS INDICATORS

- Login from an unknown external IP address.
- Login outside normal business hours.
- Authentication from an unfamiliar workstation.
- Unusual use of privileged accounts.
- Logon Type 10 from a suspicious source IP.
- NTLM authentication in unexpected circumstances.
- VPN and RDP activity inconsistent with the user's baseline.
- New user profile created close to suspicious login activity.

## END OF PLAYBOOK

An incident involving the `svc_backup` service account has been escalated for immediate forensic investigation. While the account was authenticated with valid credentials, the activity deviates from its normal baseline.

Initial evidence indicates a successful VPN authentication from an unknown external IP address, followed by an RDP connection to the server `INIT-ACC-01`. You will focus on validating that a local session was successfully established by identifying the specific Windows logon type and verifying the initialization of the user environment through Registry artifacts.

# Analysis


```python
from pathlib import Path
from IPython.display import display as ipy_display, Markdown
import re
import pandas as pd
import os
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from Registry import Registry
```


```python
for p in Path("./dataset").iterdir():
    print(p.name)
```

    rdpremote.evtx
    security.evtx
    SOFTWARE
    rdplocal.evtx
    NPS.txt
    NTUSER.DAT



```python
pd.set_option("display.max_rows", None)

# Define dataset directory
dataset_path = Path("./dataset")

# Store all DataFrames
datasets = {}

# Define Windows Event XML namespace
ns = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

# Extract nested XML elements recursively
def extract_xml(element):
    data = {}

    for child in element.iter():
        if child is element:
            continue

        tag = child.tag.split("}")[-1]

        if len(child) == 0 and child.text:
            data[tag] = child.text.strip()

    return data


# Import all EVTX datasets
for file in dataset_path.glob("*.evtx"):

    records = []

    with Evtx(str(file)) as log:
        for record in log.records():

            # Parse event XML
            root = ET.fromstring(record.xml())

            # Extract system information
            system = root.find("e:System", ns)

            row = {
                "EventRecord": record.record_num(),
                "Timestamp": record.timestamp(),
                "EventID": system.findtext("e:EventID", namespaces=ns)
                    if system is not None else None,
                "Computer": system.findtext("e:Computer", namespaces=ns)
                    if system is not None else None
            }

            # Extract EventData
            event_data = root.find("e:EventData", ns)

            if event_data is not None:
                for data in event_data.findall("e:Data", ns):
                    field_name = data.get("Name")

                    if field_name:
                        row[field_name] = data.text

            # Extract UserData
            user_data = root.find("e:UserData", ns)

            if user_data is not None:
                user_fields = extract_xml(user_data)

                for field_name, value in user_fields.items():
                    if field_name in row:
                        row[f"{field_name}_UserData"] = value
                    else:
                        row[field_name] = value

            records.append(row)

    # Create one DataFrame per dataset
    df_name = f"df_{file.stem}"

    globals()[df_name] = pd.DataFrame(records)
    datasets[df_name] = globals()[df_name]

    print(f"{df_name}: {len(records)} records imported")

# Load SOFTWARE registry hive
reg_software = Registry.Registry(str(dataset_path / "SOFTWARE"))

# Access ProfileList registry key
profile_list = reg_software.open(
    r"Microsoft\Windows NT\CurrentVersion\ProfileList"
)

# Extract user profile information
df_software = pd.DataFrame([
    {
        "SID": key.name(),
        "ProfileImagePath": next(
            (v.value() for v in key.values()
             if v.name() == "ProfileImagePath"),
            None
        ),
        "LastWriteTimestamp": key.timestamp()
    }
    for key in profile_list.subkeys()
])

# Import and parse NPS text logs
nps_path = dataset_path / "NPS.txt"
nps_records = []

for line in nps_path.read_text(errors="replace").splitlines():
    record = dict(re.findall(
        r'(?:^|\s)([A-Za-z][A-Za-z0-9-]*):\s*(.*?)(?=\s+[A-Za-z][A-Za-z0-9-]*:\s|$)',
        line
    ))

    if record:
        nps_records.append(record)

df_nps_txt = pd.DataFrame(nps_records)

def display_md(df):
    """Render a DataFrame as a Markdown table without Pandas HTML/CSS output."""
    if df.empty:
        ipy_display(Markdown("_No data available._"))
        return

    def format_cell(value):
        if value is None:
            return ""
        if not isinstance(value, (list, tuple, dict)) and pd.isna(value):
            return ""
        return str(value).replace("|", r"\|").replace("\r", "").replace("\n", "<br>")

    headers = [format_cell(column) for column in df.columns]
    rows = [
        [format_cell(value) for value in row]
        for row in df.itertuples(index=False, name=None)
    ]

    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)

    ipy_display(Markdown("\\n".join(lines)))

# Summarize all datasets
for name, df in datasets.items():

    summary_df = pd.DataFrame({
        "field": df.columns,
        "type": df.dtypes.astype(str),
        "unique_amount": [
            df[c].replace("", pd.NA).nunique(dropna=True)
            for c in df.columns
        ],
        "sample": [
            df[c].replace("", pd.NA)
                 .dropna()
                 .astype(str)
                 .drop_duplicates()
                 .head(3)
                 .tolist()
            for c in df.columns
        ]
    }).reset_index(drop=True)

    print(f"\n{'='*60}")
    print(f"DATASET SUMMARY: {name}")
    print(f"Rows: {df.shape[0]} | Columns: {df.shape[1]}")
    print(f"{'='*60}")

    display_md(summary_df)
```

    df_rdpremote: 21 records imported
    df_security: 809 records imported
    df_rdplocal: 57 records imported
    
    ============================================================
    DATASET SUMMARY: df_rdpremote
    Rows: 21 | Columns: 6
    ============================================================



| field | type | unique_amount | sample |\n| --- | --- | --- | --- |\n| EventRecord | int64 | 21 | ['1', '2', '3'] |\n| Timestamp | datetime64[us, UTC] | 21 | ['2026-05-12 04:43:20.818308+00:00', '2026-05-12 04:43:20.895859+00:00', '2026-05-12 04:53:08.132788+00:00'] |\n| EventID | str | 2 | ['261', '1149'] |\n| Computer | str | 1 | ['INIT-ACC-01.global-tek.local'] |\n| listenerName | str | 1 | ['RDP-Tcp'] |\n| Param3 | str | 4 | ['10.10.10.60', '10.10.10.53', '10.10.10.58'] |


    
    ============================================================
    DATASET SUMMARY: df_security
    Rows: 809 | Columns: 101
    ============================================================



| field | type | unique_amount | sample |\n| --- | --- | --- | --- |\n| EventRecord | int64 | 809 | ['1', '2', '3'] |\n| Timestamp | datetime64[us, UTC] | 808 | ['2026-05-12 04:29:12.171082+00:00', '2026-05-12 04:29:12.212889+00:00', '2026-05-12 04:29:12.213255+00:00'] |\n| EventID | str | 14 | ['4672', '4624', '4634'] |\n| Computer | str | 1 | ['INIT-ACC-01.global-tek.local'] |\n| SubjectUserSid | str | 11 | ['S-1-5-18', 'S-1-0-0', 'S-1-5-21-1355340450-508628708-815639551-1611'] |\n| SubjectUserName | str | 11 | ['INIT-ACC-01$', '-', 'SYSTEM'] |\n| SubjectDomainName | str | 4 | ['GLOBALTEK', '-', 'NT AUTHORITY'] |\n| SubjectLogonId | str | 200 | ['0x000000000074f90b', '0x0000000000000000', '0x000000000074f994'] |\n| PrivilegeList | str | 6 | ['SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeDelegateSessionUserImpersonatePrivilege\n\t\t\tSeEnableDelegationPrivilege', 'SeAssignPrimaryTokenPrivilege\n\t\t\tSeTcbPrivilege\n\t\t\tSeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeAuditPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeDelegateSessionUserImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege\n\t\t\tSeAuditPrivilege\n\t\t\tSeImpersonatePrivilege'] |\n| TargetUserSid | str | 22 | ['S-1-5-18', 'S-1-5-21-1355340450-508628708-815639551-500', 'S-1-5-96-0-2'] |\n| TargetUserName | str | 29 | ['INIT-ACC-01$', 'SYSTEM', 'Administrator'] |\n| TargetDomainName | str | 7 | ['GLOBAL-TEK.LOCAL', 'GLOBALTEK', 'NT AUTHORITY'] |\n| TargetLogonId | str | 272 | ['0x000000000074f90b', '0x000000000074f994', '0x000000000074fa8b'] |\n| LogonType | str | 4 | ['3', '5', '2'] |\n| LogonProcessName | str | 5 | ['Kerberos', 'Advapi  ', 'IAS'] |\n| AuthenticationPackageName | str | 4 | ['Kerberos', 'Negotiate', 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'] |\n| WorkstationName | str | 7 | ['-', 'EC2AMAZ-KNARVHI', 'INIT-ACC-01'] |\n| LogonGuid | str | 18 | ['{0dd8d67e-0df5-5f72-55ca-0486fe97152f}', '{903774c9-cc87-f74d-a4fa-7e9a0410c190}', '{a58c8785-c0a2-712a-a937-b99445f2f70d}'] |\n| TransmittedServices | str | 1 | ['-'] |\n| LmPackageName | str | 2 | ['-', 'NTLM V2'] |\n| KeyLength | str | 2 | ['0', '128'] |\n| ProcessId | str | 12 | ['0x0000000000000000', '0x0000000000000248', '0x0000000000000640'] |\n| ProcessName | str | 4 | ['-', 'C:\\Windows\\System32\\services.exe', 'C:\\Windows\\System32\\svchost.exe'] |\n| IpAddress | str | 9 | ['fe80::116e:b6a8:bd4b:d6f1', '::1', '172.31.17.190'] |\n| IpPort | str | 155 | ['51839', '51840', '0'] |\n| ImpersonationLevel | str | 2 | ['%%1833', '%%1840'] |\n| RestrictedAdminMode | str | 2 | ['-', '%%1843'] |\n| TargetOutboundUserName | str | 1 | ['-'] |\n| TargetOutboundDomainName | str | 1 | ['-'] |\n| VirtualAccount | str | 2 | ['%%1843', '%%1842'] |\n| TargetLinkedLogonId | str | 49 | ['0x0000000000000000', '0x000000000076f2d1', '0x000000000076f12b'] |\n| ElevatedToken | str | 2 | ['%%1842', '%%1843'] |\n| ObjectServer | str | 1 | ['DS'] |\n| ObjectType | str | 1 | ['%{19195a5b-6da0-11d0-afd3-00c04fd930c9}'] |\n| ObjectName | str | 1 | ['%{bdb4ca05-9e6c-48ae-96c4-026c917decd9}'] |\n| OperationType | str | 1 | ['Object Access'] |\n| HandleId | str | 1 | ['0x0000000000000000'] |\n| AccessList | str | 1 | ['%%7688\n\t\t\t\t'] |\n| AccessMask | str | 1 | ['0x00000100'] |\n| Properties | str | 1 | ['%%7688\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}\n'] |\n| AdditionalInfo | str | 1 | ['-'] |\n| AdditionalInfo2 | float64 | 0 | [] |\n| PackageName | str | 1 | ['MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'] |\n| Workstation | str | 5 | ['EC2AMAZ-KNARVHI', 'EC2AMAZ-K4E6AT6', 'EC2AMAZ-PIQU25B'] |\n| Status | str | 1 | ['0x00000000'] |\n| TargetLogonGuid | str | 11 | ['{00000000-0000-0000-0000-000000000000}', '{b18d926a-a327-0185-3c08-1b9b62922cb9}', '{1fba2d10-5b0e-2650-4b14-fb39747d33f2}'] |\n| TargetServerName | str | 2 | ['localhost', 'INIT-ACC-01.global-tek.local'] |\n| TargetInfo | str | 2 | ['localhost', 'ldap/INIT-ACC-01.global-tek.local'] |\n| TargetSid | str | 7 | ['S-1-5-21-1355340450-508628708-815639551-1008', 'S-1-5-21-1355340450-508628708-815639551-1610', 'S-1-5-32-544'] |\n| ServiceName | str | 2 | ['krbtgt', 'INIT-ACC-01$'] |\n| ServiceSid | str | 2 | ['S-1-5-21-1355340450-508628708-815639551-502', 'S-1-5-21-1355340450-508628708-815639551-1008'] |\n| TicketOptions | str | 2 | ['0x40810010', '0x40810000'] |\n| TicketEncryptionType | str | 1 | ['0x00000012'] |\n| PreAuthType | str | 1 | ['2'] |\n| CertIssuerName | float64 | 0 | [] |\n| CertSerialNumber | float64 | 0 | [] |\n| CertThumbprint | float64 | 0 | [] |\n| ResponseTicket | str | 10 | ['CIJNzF+b9drfxoQDlhFCEfv8FUuvndLIJMsM6iP6hjY=', 'jquzyqnUMbxjZR0TAm3O7cvJ68bpPx+/P6v5FH0aM80=', 'FrQYSHRiqmg4iaAHlb0VZUatMemo7x2n6IdhRV6vhks='] |\n| AccountSupportedEncryptionTypes | str | 3 | ['0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)', 'N/A', '0x18 (AES128-SHA96, AES256-SHA96)'] |\n| AccountAvailableKeys | str | 2 | ['AES-SHA1, RC4', 'N/A'] |\n| ServiceSupportedEncryptionTypes | str | 1 | ['0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)'] |\n| ServiceAvailableKeys | str | 1 | ['AES-SHA1, RC4'] |\n| DCSupportedEncryptionTypes | str | 1 | ['0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)'] |\n| DCAvailableKeys | str | 1 | ['AES-SHA1, RC4'] |\n| ClientAdvertizedEncryptionTypes | str | 3 | ['\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tRC4-HMAC-NT\n\t\tRC4-HMAC-OLD\n\t\tRC4-MD4\n\t\tRC4-HMAC-NT-EXP\n\t\tRC4-HMAC-OLD-EXP', '\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96\n\t\tRC4-HMAC-NT\n\t\tRC4-HMAC-NT-EXP\n\t\tRC4-HMAC-OLD-EXP', '\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96\n\t\tRC4-HMAC-NT\n\t\tRC4-HMAC-NT-EXP\n\t\tRC4-HMAC-OLD-EXP\n\t\tDES-CBC-MD5'] |\n| SessionKeyEncryptionType | str | 1 | ['0x00000012'] |\n| PreAuthEncryptionType | str | 1 | ['0x00000012'] |\n| RequestTicketHash | str | 10 | ['CIJNzF+b9drfxoQDlhFCEfv8FUuvndLIJMsM6iP6hjY=', 'jquzyqnUMbxjZR0TAm3O7cvJ68bpPx+/P6v5FH0aM80=', 'FrQYSHRiqmg4iaAHlb0VZUatMemo7x2n6IdhRV6vhks='] |\n| ResponseTicketHash | str | 10 | ['sHU3KD4rFVuKtPW9+Ip5YwM1egZv1rJPOBb6KxakK1A=', 'IwpS4AmwBXXYnSeaRUqGsng98GrNhyUcimew1FetA5M=', 'CE1MxscmYHxYqRhYO0vB7JLlLgXj7LdII48hWc6TFho='] |\n| FullyQualifiedSubjectUserName | str | 5 | ['global-tek.local/Users/it_bhardy', 'global-tek.local/Users/hr_jsmith', 'global-tek.local/Users/fin_dwright'] |\n| SubjectMachineSID | str | 1 | ['S-1-0-0'] |\n| SubjectMachineName | str | 1 | ['-'] |\n| FullyQualifiedSubjectMachineName | str | 1 | ['-'] |\n| CalledStationID | str | 1 | ['172.31.17.190'] |\n| CallingStationID | str | 5 | ['15.135.92.124', '3.25.161.84', '15.135.87.2'] |\n| NASIPv4Address | str | 1 | ['172.31.17.190'] |\n| NASIPv6Address | str | 1 | ['-'] |\n| NASIdentifier | str | 1 | ['INIT-ACC-01'] |\n| NASPortType | str | 1 | ['Virtual'] |\n| NASPort | str | 5 | ['129', '130', '131'] |\n| ClientName | str | 1 | ['INIT-ACC-01'] |\n| ClientIPAddress | str | 1 | ['172.31.17.190'] |\n| ProxyPolicyName | str | 1 | ['Microsoft Routing and Remote Access Service Policy'] |\n| NetworkPolicyName | str | 2 | ['Connections to Microsoft Routing and Remote Access server', 'VPN_Allow'] |\n| AuthenticationProvider | str | 1 | ['Windows'] |\n| AuthenticationServer | str | 1 | ['INIT-ACC-01.global-tek.local'] |\n| AuthenticationType | str | 1 | ['MS-CHAPv2'] |\n| EAPType | str | 1 | ['-'] |\n| AccountSessionIdentifier | str | 5 | ['3139', '3230', '3231'] |\n| LoggingResult | str | 1 | ['Accounting information was not written to any data store.'] |\n| CallerProcessId | str | 2 | ['0x00000000000003c0', '0x00000000000004e8'] |\n| CallerProcessName | str | 2 | ['C:\\Windows\\System32\\consent.exe', 'C:\\Windows\\System32\\svchost.exe'] |\n| ClientProcessId | str | 3 | ['8196', '4180', '7220'] |\n| ClientCreationTime | str | 3 | ['2026-05-12 04:43:48.658352+00:00', '2026-05-12 05:06:36.070669+00:00', '2026-05-12 05:19:33.830389+00:00'] |\n| ProviderName | str | 1 | ['Microsoft Software Key Storage Provider'] |\n| AlgorithmName | str | 3 | ['UNKNOWN', 'AES', 'ECDSA_P256'] |\n| KeyName | str | 2 | ['Google Chromekey1', 'Microsoft Connected Devices Platform device certificate'] |\n| KeyType | str | 1 | ['%%2500'] |\n| KeyFilePath | str | 3 | ['C:\\ProgramData\\Microsoft\\Crypto\\SystemKeys\\7096db7aeb75c0d3497ecd56d355a695_0305366a-2d34-4125-a54a-9621bff11f32', 'C:\\Users\\it_bhardy\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\\de7cf8a7901d2ad13e5c67c29e5d1662_0305366a-2d34-4125-a54a-9621bff11f32', 'C:\\Users\\adm_jross\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\\de7cf8a7901d2ad13e5c67c29e5d1662_0305366a-2d34-4125-a54a-9621bff11f32'] |\n| Operation | str | 3 | ['%%2458', '%%2480', '%%2464'] |\n| ReturnCode | str | 1 | ['0x00000000'] |


    
    ============================================================
    DATASET SUMMARY: df_rdplocal
    Rows: 57 | Columns: 9
    ============================================================



| field | type | unique_amount | sample |\n| --- | --- | --- | --- |\n| EventRecord | int64 | 57 | ['1', '2', '3'] |\n| Timestamp | datetime64[us, UTC] | 57 | ['2026-05-12 04:38:02.508286+00:00', '2026-05-12 04:38:02.657610+00:00', '2026-05-12 04:38:04.301229+00:00'] |\n| EventID | str | 8 | ['41', '40', '25'] |\n| Computer | str | 1 | ['INIT-ACC-01.global-tek.local'] |\n| User | str | 5 | ['GLOBALTEK\\hr_jsmith', 'GLOBALTEK\\it_bhardy', 'GLOBALTEK\\fin_dwright'] |\n| SessionID | str | 6 | ['8', '4', '3'] |\n| Session | str | 6 | ['8', '4', '3'] |\n| Reason | str | 3 | ['0', '5', '12'] |\n| Address | str | 5 | ['10.10.10.61', '10.10.10.60', '10.10.10.53'] |


# Hands-On Investigation

### Question 1 — NPS Access Granted Time

At what time was access granted to the `svc_backup` account by the Network Policy Server?

**Investigation focus:** Identify the successful NPS authentication event (`Event ID 6272`) and record its `Timestamp`.


```python
# Identify successful NPS authentication
result = df_security[
    (df_security["EventID"] == "6272") &
    (df_security["FullyQualifiedSubjectUserName"].str.contains("svc_backup", case=False, na=False))
][["Timestamp", "EventID", "FullyQualifiedSubjectUserName", "CallingStationID", "CalledStationID"]]

display_md(result)
```


| Timestamp | EventID | FullyQualifiedSubjectUserName | CallingStationID | CalledStationID |\n| --- | --- | --- | --- | --- |\n| 2026-05-12 05:11:57.581541+00:00 | 6272 | global-tek.local/Users/svc_backup | 216.128.153.60 | 172.31.17.190 |


### Question 2 — Attacker's Remote IP Address

What remote IP address did the attacker use to connect to the target machine?

**Investigation focus:** Examine the `CallingStationID` field in the successful NPS authentication event (`Event ID 6272`) for `svc_backup`.


```python
# Identify successful NPS authentication
result = df_security[
    (df_security["EventID"] == "6272") &
    (df_security["FullyQualifiedSubjectUserName"].str.contains("svc_backup", case=False, na=False))
][["Timestamp", "EventID", "CallingStationID"]]

display_md(result)
```


| Timestamp | EventID | CallingStationID |\n| --- | --- | --- |\n| 2026-05-12 05:11:57.581541+00:00 | 6272 | 216.128.153.60 |


### Question 3 — Assigned VPN Pool IP Address

What VPN pool IP address was assigned to the `svc_backup` session?


```python
# Identify assigned VPN pool IP
result = df_nps_txt[
    df_nps_txt["User-Name"].str.contains("svc_backup", case=False, na=False)
][["Timestamp", "User-Name", "Framed-IP-Address"]]

display_md(result)
```


| Timestamp | User-Name | Framed-IP-Address |\n| --- | --- | --- |\n| 05/12/2026 05:11:37.000 | svc_backup | 10.10.10.58 |


### Question 4 — Successful Logon GUID

What is the unique Logon GUID associated with the `svc_backup` user's successful Type 10 logon?


```python
# Identify successful RDP logon
result = df_security[
    (df_security["EventID"] == "4624") &
    (df_security["TargetUserName"] == "svc_backup") &
    (df_security["LogonType"] == "10")
][["Timestamp", "TargetUserName", "LogonType", "IpAddress", "LogonGuid", "TargetLogonId"]]

display_md(result)
```


| Timestamp | TargetUserName | LogonType | IpAddress | LogonGuid | TargetLogonId |\n| --- | --- | --- | --- | --- | --- |\n| 2026-05-12 05:13:11.481781+00:00 | svc_backup | 10 | 10.10.10.58 | {9d4f92d8-07cb-fde3-ae92-151f5d1e1a82} | 0x00000000009b3c9a |\n| 2026-05-12 05:13:11.481789+00:00 | svc_backup | 10 | 10.10.10.58 | {00000000-0000-0000-0000-000000000000} | 0x00000000009b3cc4 |


### Question 5 — RDP Session ID

What Session ID was assigned to the successful RDP logon?

**Investigation focus:** Identify the RDP session event by filtering `assigned VPN pool IP`.


```python
# Display RDP session events for the assigned VPN pool IP
result = df_rdplocal[
    df_rdplocal["Address"] == "10.10.10.58"
][["Timestamp", "EventID", "User", "SessionID", "Address"]]

display_md(result)
```


| Timestamp | EventID | User | SessionID | Address |\n| --- | --- | --- | --- | --- |\n| 2026-05-12 05:13:13.131023+00:00 | 25 | GLOBALTEK\svc_backup | 7 | 10.10.10.58 |\n| 2026-05-12 05:33:51.360374+00:00 | 24 | GLOBALTEK\svc_backup | 7 | 10.10.10.58 |


### Question 6 — ProfileList Registry Last Write Timestamp

What is the Last Write Timestamp for the `svc_backup` user's ProfileList registry key?

**Investigation focus:** Locate the `svc_backup` profile under `Microsoft\Windows NT\CurrentVersion\ProfileList` and record its `LastWriteTimestamp`.


```python
# Identify svc_backup profile
result = df_software[
    df_software["ProfileImagePath"].str.contains(
        "svc_backup", case=False, na=False
    )
]

display_md(result)
```


| SID | ProfileImagePath | LastWriteTimestamp |\n| --- | --- | --- |\n| S-1-5-21-1355340450-508628708-815639551-1112 | C:\Users\svc_backup | 2026-05-12 05:32:27.092868 |

