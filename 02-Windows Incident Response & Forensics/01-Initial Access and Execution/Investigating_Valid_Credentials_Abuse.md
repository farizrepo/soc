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


# Case

An incident involving the `svc_backup` service account has been escalated for immediate forensic investigation. While the account was authenticated with valid credentials, the activity deviates from its normal baseline.

Initial evidence indicates a successful VPN authentication from an unknown external IP address, followed by an RDP connection to the server `INIT-ACC-01`. You will focus on validating that a local session was successfully established by identifying the specific Windows logon type and verifying the initialization of the user environment through Registry artifacts.

# Initialization


```python
from pathlib import Path
import re
import pandas as pd
import os
from pathlib import Path
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from Registry import Registry
```

Data source list
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


Data processing
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

    display(summary_df)
```

    df_rdpremote: 21 records imported
    df_security: 809 records imported
    df_rdplocal: 57 records imported
    
    ============================================================
    DATASET SUMMARY: df_rdpremote
    Rows: 21 | Columns: 6
    ============================================================



<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>field</th>
      <th>type</th>
      <th>unique_amount</th>
      <th>sample</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>EventRecord</td>
      <td>int64</td>
      <td>21</td>
      <td>[1, 2, 3]</td>
    </tr>
    <tr>
      <th>1</th>
      <td>Timestamp</td>
      <td>datetime64[us, UTC]</td>
      <td>21</td>
      <td>[2026-05-12 04:43:20.818308+00:00, 2026-05-12 ...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>EventID</td>
      <td>str</td>
      <td>2</td>
      <td>[261, 1149]</td>
    </tr>
    <tr>
      <th>3</th>
      <td>Computer</td>
      <td>str</td>
      <td>1</td>
      <td>[INIT-ACC-01.global-tek.local]</td>
    </tr>
    <tr>
      <th>4</th>
      <td>listenerName</td>
      <td>str</td>
      <td>1</td>
      <td>[RDP-Tcp]</td>
    </tr>
    <tr>
      <th>5</th>
      <td>Param3</td>
      <td>str</td>
      <td>4</td>
      <td>[10.10.10.60, 10.10.10.53, 10.10.10.58]</td>
    </tr>
  </tbody>
</table>
</div>


    
    ============================================================
    DATASET SUMMARY: df_security
    Rows: 809 | Columns: 101
    ============================================================



<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>field</th>
      <th>type</th>
      <th>unique_amount</th>
      <th>sample</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>EventRecord</td>
      <td>int64</td>
      <td>809</td>
      <td>[1, 2, 3]</td>
    </tr>
    <tr>
      <th>1</th>
      <td>Timestamp</td>
      <td>datetime64[us, UTC]</td>
      <td>808</td>
      <td>[2026-05-12 04:29:12.171082+00:00, 2026-05-12 ...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>EventID</td>
      <td>str</td>
      <td>14</td>
      <td>[4672, 4624, 4634]</td>
    </tr>
    <tr>
      <th>3</th>
      <td>Computer</td>
      <td>str</td>
      <td>1</td>
      <td>[INIT-ACC-01.global-tek.local]</td>
    </tr>
    <tr>
      <th>4</th>
      <td>SubjectUserSid</td>
      <td>str</td>
      <td>11</td>
      <td>[S-1-5-18, S-1-0-0, S-1-5-21-1355340450-508628...</td>
    </tr>
    <tr>
      <th>5</th>
      <td>SubjectUserName</td>
      <td>str</td>
      <td>11</td>
      <td>[INIT-ACC-01$, -, SYSTEM]</td>
    </tr>
    <tr>
      <th>6</th>
      <td>SubjectDomainName</td>
      <td>str</td>
      <td>4</td>
      <td>[GLOBALTEK, -, NT AUTHORITY]</td>
    </tr>
    <tr>
      <th>7</th>
      <td>SubjectLogonId</td>
      <td>str</td>
      <td>200</td>
      <td>[0x000000000074f90b, 0x0000000000000000, 0x000...</td>
    </tr>
    <tr>
      <th>8</th>
      <td>PrivilegeList</td>
      <td>str</td>
      <td>6</td>
      <td>[SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\...</td>
    </tr>
    <tr>
      <th>9</th>
      <td>TargetUserSid</td>
      <td>str</td>
      <td>22</td>
      <td>[S-1-5-18, S-1-5-21-1355340450-508628708-81563...</td>
    </tr>
    <tr>
      <th>10</th>
      <td>TargetUserName</td>
      <td>str</td>
      <td>29</td>
      <td>[INIT-ACC-01$, SYSTEM, Administrator]</td>
    </tr>
    <tr>
      <th>11</th>
      <td>TargetDomainName</td>
      <td>str</td>
      <td>7</td>
      <td>[GLOBAL-TEK.LOCAL, GLOBALTEK, NT AUTHORITY]</td>
    </tr>
    <tr>
      <th>12</th>
      <td>TargetLogonId</td>
      <td>str</td>
      <td>272</td>
      <td>[0x000000000074f90b, 0x000000000074f994, 0x000...</td>
    </tr>
    <tr>
      <th>13</th>
      <td>LogonType</td>
      <td>str</td>
      <td>4</td>
      <td>[3, 5, 2]</td>
    </tr>
    <tr>
      <th>14</th>
      <td>LogonProcessName</td>
      <td>str</td>
      <td>5</td>
      <td>[Kerberos, Advapi&nbsp;&nbsp;, IAS]</td>
    </tr>
    <tr>
      <th>15</th>
      <td>AuthenticationPackageName</td>
      <td>str</td>
      <td>4</td>
      <td>[Kerberos, Negotiate, MICROSOFT_AUTHENTICATION...</td>
    </tr>
    <tr>
      <th>16</th>
      <td>WorkstationName</td>
      <td>str</td>
      <td>7</td>
      <td>[-, EC2AMAZ-KNARVHI, INIT-ACC-01]</td>
    </tr>
    <tr>
      <th>17</th>
      <td>LogonGuid</td>
      <td>str</td>
      <td>18</td>
      <td>[{0dd8d67e-0df5-5f72-55ca-0486fe97152f}, {9037...</td>
    </tr>
    <tr>
      <th>18</th>
      <td>TransmittedServices</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>19</th>
      <td>LmPackageName</td>
      <td>str</td>
      <td>2</td>
      <td>[-, NTLM V2]</td>
    </tr>
    <tr>
      <th>20</th>
      <td>KeyLength</td>
      <td>str</td>
      <td>2</td>
      <td>[0, 128]</td>
    </tr>
    <tr>
      <th>21</th>
      <td>ProcessId</td>
      <td>str</td>
      <td>12</td>
      <td>[0x0000000000000000, 0x0000000000000248, 0x000...</td>
    </tr>
    <tr>
      <th>22</th>
      <td>ProcessName</td>
      <td>str</td>
      <td>4</td>
      <td>[-, C:\Windows\System32\services.exe, C:\Windo...</td>
    </tr>
    <tr>
      <th>23</th>
      <td>IpAddress</td>
      <td>str</td>
      <td>9</td>
      <td>[fe80::116e:b6a8:bd4b:d6f1, ::1, 172.31.17.190]</td>
    </tr>
    <tr>
      <th>24</th>
      <td>IpPort</td>
      <td>str</td>
      <td>155</td>
      <td>[51839, 51840, 0]</td>
    </tr>
    <tr>
      <th>25</th>
      <td>ImpersonationLevel</td>
      <td>str</td>
      <td>2</td>
      <td>[%%1833, %%1840]</td>
    </tr>
    <tr>
      <th>26</th>
      <td>RestrictedAdminMode</td>
      <td>str</td>
      <td>2</td>
      <td>[-, %%1843]</td>
    </tr>
    <tr>
      <th>27</th>
      <td>TargetOutboundUserName</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>28</th>
      <td>TargetOutboundDomainName</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>29</th>
      <td>VirtualAccount</td>
      <td>str</td>
      <td>2</td>
      <td>[%%1843, %%1842]</td>
    </tr>
    <tr>
      <th>30</th>
      <td>TargetLinkedLogonId</td>
      <td>str</td>
      <td>49</td>
      <td>[0x0000000000000000, 0x000000000076f2d1, 0x000...</td>
    </tr>
    <tr>
      <th>31</th>
      <td>ElevatedToken</td>
      <td>str</td>
      <td>2</td>
      <td>[%%1842, %%1843]</td>
    </tr>
    <tr>
      <th>32</th>
      <td>ObjectServer</td>
      <td>str</td>
      <td>1</td>
      <td>[DS]</td>
    </tr>
    <tr>
      <th>33</th>
      <td>ObjectType</td>
      <td>str</td>
      <td>1</td>
      <td>[%{19195a5b-6da0-11d0-afd3-00c04fd930c9}]</td>
    </tr>
    <tr>
      <th>34</th>
      <td>ObjectName</td>
      <td>str</td>
      <td>1</td>
      <td>[%{bdb4ca05-9e6c-48ae-96c4-026c917decd9}]</td>
    </tr>
    <tr>
      <th>35</th>
      <td>OperationType</td>
      <td>str</td>
      <td>1</td>
      <td>[Object Access]</td>
    </tr>
    <tr>
      <th>36</th>
      <td>HandleId</td>
      <td>str</td>
      <td>1</td>
      <td>[0x0000000000000000]</td>
    </tr>
    <tr>
      <th>37</th>
      <td>AccessList</td>
      <td>str</td>
      <td>1</td>
      <td>[%%7688\n\t\t\t\t]</td>
    </tr>
    <tr>
      <th>38</th>
      <td>AccessMask</td>
      <td>str</td>
      <td>1</td>
      <td>[0x00000100]</td>
    </tr>
    <tr>
      <th>39</th>
      <td>Properties</td>
      <td>str</td>
      <td>1</td>
      <td>[%%7688\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2...</td>
    </tr>
    <tr>
      <th>40</th>
      <td>AdditionalInfo</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>41</th>
      <td>AdditionalInfo2</td>
      <td>float64</td>
      <td>0</td>
      <td>[]</td>
    </tr>
    <tr>
      <th>42</th>
      <td>PackageName</td>
      <td>str</td>
      <td>1</td>
      <td>[MICROSOFT_AUTHENTICATION_PACKAGE_V1_0]</td>
    </tr>
    <tr>
      <th>43</th>
      <td>Workstation</td>
      <td>str</td>
      <td>5</td>
      <td>[EC2AMAZ-KNARVHI, EC2AMAZ-K4E6AT6, EC2AMAZ-PIQ...</td>
    </tr>
    <tr>
      <th>44</th>
      <td>Status</td>
      <td>str</td>
      <td>1</td>
      <td>[0x00000000]</td>
    </tr>
    <tr>
      <th>45</th>
      <td>TargetLogonGuid</td>
      <td>str</td>
      <td>11</td>
      <td>[{00000000-0000-0000-0000-000000000000}, {b18d...</td>
    </tr>
    <tr>
      <th>46</th>
      <td>TargetServerName</td>
      <td>str</td>
      <td>2</td>
      <td>[localhost, INIT-ACC-01.global-tek.local]</td>
    </tr>
    <tr>
      <th>47</th>
      <td>TargetInfo</td>
      <td>str</td>
      <td>2</td>
      <td>[localhost, ldap/INIT-ACC-01.global-tek.local]</td>
    </tr>
    <tr>
      <th>48</th>
      <td>TargetSid</td>
      <td>str</td>
      <td>7</td>
      <td>[S-1-5-21-1355340450-508628708-815639551-1008,...</td>
    </tr>
    <tr>
      <th>49</th>
      <td>ServiceName</td>
      <td>str</td>
      <td>2</td>
      <td>[krbtgt, INIT-ACC-01$]</td>
    </tr>
    <tr>
      <th>50</th>
      <td>ServiceSid</td>
      <td>str</td>
      <td>2</td>
      <td>[S-1-5-21-1355340450-508628708-815639551-502, ...</td>
    </tr>
    <tr>
      <th>51</th>
      <td>TicketOptions</td>
      <td>str</td>
      <td>2</td>
      <td>[0x40810010, 0x40810000]</td>
    </tr>
    <tr>
      <th>52</th>
      <td>TicketEncryptionType</td>
      <td>str</td>
      <td>1</td>
      <td>[0x00000012]</td>
    </tr>
    <tr>
      <th>53</th>
      <td>PreAuthType</td>
      <td>str</td>
      <td>1</td>
      <td>[2]</td>
    </tr>
    <tr>
      <th>54</th>
      <td>CertIssuerName</td>
      <td>float64</td>
      <td>0</td>
      <td>[]</td>
    </tr>
    <tr>
      <th>55</th>
      <td>CertSerialNumber</td>
      <td>float64</td>
      <td>0</td>
      <td>[]</td>
    </tr>
    <tr>
      <th>56</th>
      <td>CertThumbprint</td>
      <td>float64</td>
      <td>0</td>
      <td>[]</td>
    </tr>
    <tr>
      <th>57</th>
      <td>ResponseTicket</td>
      <td>str</td>
      <td>10</td>
      <td>[CIJNzF+b9drfxoQDlhFCEfv8FUuvndLIJMsM6iP6hjY=,...</td>
    </tr>
    <tr>
      <th>58</th>
      <td>AccountSupportedEncryptionTypes</td>
      <td>str</td>
      <td>3</td>
      <td>[0x1F (DES, RC4, AES128-SHA96, AES256-SHA96), ...</td>
    </tr>
    <tr>
      <th>59</th>
      <td>AccountAvailableKeys</td>
      <td>str</td>
      <td>2</td>
      <td>[AES-SHA1, RC4, N/A]</td>
    </tr>
    <tr>
      <th>60</th>
      <td>ServiceSupportedEncryptionTypes</td>
      <td>str</td>
      <td>1</td>
      <td>[0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)]</td>
    </tr>
    <tr>
      <th>61</th>
      <td>ServiceAvailableKeys</td>
      <td>str</td>
      <td>1</td>
      <td>[AES-SHA1, RC4]</td>
    </tr>
    <tr>
      <th>62</th>
      <td>DCSupportedEncryptionTypes</td>
      <td>str</td>
      <td>1</td>
      <td>[0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)]</td>
    </tr>
    <tr>
      <th>63</th>
      <td>DCAvailableKeys</td>
      <td>str</td>
      <td>1</td>
      <td>[AES-SHA1, RC4]</td>
    </tr>
    <tr>
      <th>64</th>
      <td>ClientAdvertizedEncryptionTypes</td>
      <td>str</td>
      <td>3</td>
      <td>[\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tRC4-HMAC-N...</td>
    </tr>
    <tr>
      <th>65</th>
      <td>SessionKeyEncryptionType</td>
      <td>str</td>
      <td>1</td>
      <td>[0x00000012]</td>
    </tr>
    <tr>
      <th>66</th>
      <td>PreAuthEncryptionType</td>
      <td>str</td>
      <td>1</td>
      <td>[0x00000012]</td>
    </tr>
    <tr>
      <th>67</th>
      <td>RequestTicketHash</td>
      <td>str</td>
      <td>10</td>
      <td>[CIJNzF+b9drfxoQDlhFCEfv8FUuvndLIJMsM6iP6hjY=,...</td>
    </tr>
    <tr>
      <th>68</th>
      <td>ResponseTicketHash</td>
      <td>str</td>
      <td>10</td>
      <td>[sHU3KD4rFVuKtPW9+Ip5YwM1egZv1rJPOBb6KxakK1A=,...</td>
    </tr>
    <tr>
      <th>69</th>
      <td>FullyQualifiedSubjectUserName</td>
      <td>str</td>
      <td>5</td>
      <td>[global-tek.local/Users/it_bhardy, global-tek....</td>
    </tr>
    <tr>
      <th>70</th>
      <td>SubjectMachineSID</td>
      <td>str</td>
      <td>1</td>
      <td>[S-1-0-0]</td>
    </tr>
    <tr>
      <th>71</th>
      <td>SubjectMachineName</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>72</th>
      <td>FullyQualifiedSubjectMachineName</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>73</th>
      <td>CalledStationID</td>
      <td>str</td>
      <td>1</td>
      <td>[172.31.17.190]</td>
    </tr>
    <tr>
      <th>74</th>
      <td>CallingStationID</td>
      <td>str</td>
      <td>5</td>
      <td>[15.135.92.124, 3.25.161.84, 15.135.87.2]</td>
    </tr>
    <tr>
      <th>75</th>
      <td>NASIPv4Address</td>
      <td>str</td>
      <td>1</td>
      <td>[172.31.17.190]</td>
    </tr>
    <tr>
      <th>76</th>
      <td>NASIPv6Address</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>77</th>
      <td>NASIdentifier</td>
      <td>str</td>
      <td>1</td>
      <td>[INIT-ACC-01]</td>
    </tr>
    <tr>
      <th>78</th>
      <td>NASPortType</td>
      <td>str</td>
      <td>1</td>
      <td>[Virtual]</td>
    </tr>
    <tr>
      <th>79</th>
      <td>NASPort</td>
      <td>str</td>
      <td>5</td>
      <td>[129, 130, 131]</td>
    </tr>
    <tr>
      <th>80</th>
      <td>ClientName</td>
      <td>str</td>
      <td>1</td>
      <td>[INIT-ACC-01]</td>
    </tr>
    <tr>
      <th>81</th>
      <td>ClientIPAddress</td>
      <td>str</td>
      <td>1</td>
      <td>[172.31.17.190]</td>
    </tr>
    <tr>
      <th>82</th>
      <td>ProxyPolicyName</td>
      <td>str</td>
      <td>1</td>
      <td>[Microsoft Routing and Remote Access Service P...</td>
    </tr>
    <tr>
      <th>83</th>
      <td>NetworkPolicyName</td>
      <td>str</td>
      <td>2</td>
      <td>[Connections to Microsoft Routing and Remote A...</td>
    </tr>
    <tr>
      <th>84</th>
      <td>AuthenticationProvider</td>
      <td>str</td>
      <td>1</td>
      <td>[Windows]</td>
    </tr>
    <tr>
      <th>85</th>
      <td>AuthenticationServer</td>
      <td>str</td>
      <td>1</td>
      <td>[INIT-ACC-01.global-tek.local]</td>
    </tr>
    <tr>
      <th>86</th>
      <td>AuthenticationType</td>
      <td>str</td>
      <td>1</td>
      <td>[MS-CHAPv2]</td>
    </tr>
    <tr>
      <th>87</th>
      <td>EAPType</td>
      <td>str</td>
      <td>1</td>
      <td>[-]</td>
    </tr>
    <tr>
      <th>88</th>
      <td>AccountSessionIdentifier</td>
      <td>str</td>
      <td>5</td>
      <td>[3139, 3230, 3231]</td>
    </tr>
    <tr>
      <th>89</th>
      <td>LoggingResult</td>
      <td>str</td>
      <td>1</td>
      <td>[Accounting information was not written to any...</td>
    </tr>
    <tr>
      <th>90</th>
      <td>CallerProcessId</td>
      <td>str</td>
      <td>2</td>
      <td>[0x00000000000003c0, 0x00000000000004e8]</td>
    </tr>
    <tr>
      <th>91</th>
      <td>CallerProcessName</td>
      <td>str</td>
      <td>2</td>
      <td>[C:\Windows\System32\consent.exe, C:\Windows\S...</td>
    </tr>
    <tr>
      <th>92</th>
      <td>ClientProcessId</td>
      <td>str</td>
      <td>3</td>
      <td>[8196, 4180, 7220]</td>
    </tr>
    <tr>
      <th>93</th>
      <td>ClientCreationTime</td>
      <td>str</td>
      <td>3</td>
      <td>[2026-05-12 04:43:48.658352+00:00, 2026-05-12 ...</td>
    </tr>
    <tr>
      <th>94</th>
      <td>ProviderName</td>
      <td>str</td>
      <td>1</td>
      <td>[Microsoft Software Key Storage Provider]</td>
    </tr>
    <tr>
      <th>95</th>
      <td>AlgorithmName</td>
      <td>str</td>
      <td>3</td>
      <td>[UNKNOWN, AES, ECDSA_P256]</td>
    </tr>
    <tr>
      <th>96</th>
      <td>KeyName</td>
      <td>str</td>
      <td>2</td>
      <td>[Google Chromekey1, Microsoft Connected Device...</td>
    </tr>
    <tr>
      <th>97</th>
      <td>KeyType</td>
      <td>str</td>
      <td>1</td>
      <td>[%%2500]</td>
    </tr>
    <tr>
      <th>98</th>
      <td>KeyFilePath</td>
      <td>str</td>
      <td>3</td>
      <td>[C:\ProgramData\Microsoft\Crypto\SystemKeys\70...</td>
    </tr>
    <tr>
      <th>99</th>
      <td>Operation</td>
      <td>str</td>
      <td>3</td>
      <td>[%%2458, %%2480, %%2464]</td>
    </tr>
    <tr>
      <th>100</th>
      <td>ReturnCode</td>
      <td>str</td>
      <td>1</td>
      <td>[0x00000000]</td>
    </tr>
  </tbody>
</table>
</div>


    
    ============================================================
    DATASET SUMMARY: df_rdplocal
    Rows: 57 | Columns: 9
    ============================================================



<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>field</th>
      <th>type</th>
      <th>unique_amount</th>
      <th>sample</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>EventRecord</td>
      <td>int64</td>
      <td>57</td>
      <td>[1, 2, 3]</td>
    </tr>
    <tr>
      <th>1</th>
      <td>Timestamp</td>
      <td>datetime64[us, UTC]</td>
      <td>57</td>
      <td>[2026-05-12 04:38:02.508286+00:00, 2026-05-12 ...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>EventID</td>
      <td>str</td>
      <td>8</td>
      <td>[41, 40, 25]</td>
    </tr>
    <tr>
      <th>3</th>
      <td>Computer</td>
      <td>str</td>
      <td>1</td>
      <td>[INIT-ACC-01.global-tek.local]</td>
    </tr>
    <tr>
      <th>4</th>
      <td>User</td>
      <td>str</td>
      <td>5</td>
      <td>[GLOBALTEK\hr_jsmith, GLOBALTEK\it_bhardy, GLO...</td>
    </tr>
    <tr>
      <th>5</th>
      <td>SessionID</td>
      <td>str</td>
      <td>6</td>
      <td>[8, 4, 3]</td>
    </tr>
    <tr>
      <th>6</th>
      <td>Session</td>
      <td>str</td>
      <td>6</td>
      <td>[8, 4, 3]</td>
    </tr>
    <tr>
      <th>7</th>
      <td>Reason</td>
      <td>str</td>
      <td>3</td>
      <td>[0, 5, 12]</td>
    </tr>
    <tr>
      <th>8</th>
      <td>Address</td>
      <td>str</td>
      <td>5</td>
      <td>[10.10.10.61, 10.10.10.60, 10.10.10.53]</td>
    </tr>
  </tbody>
</table>
</div>


# Hands-On Investigation

### Question 1 — NPS Access Granted Time

At what time was access granted to the `svc_backup` account by the Network Policy Server?

**Investigation focus:** Identify the successful NPS authentication event (`Event ID 6272`) and record its `Timestamp`.


```python
# Identify successful NPS authentication
df_security[
    (df_security["EventID"] == "6272") &
    (df_security["FullyQualifiedSubjectUserName"].str.contains("svc_backup", case=False, na=False))
][["Timestamp", "EventID", "FullyQualifiedSubjectUserName","CallingStationID", "CalledStationID"]]
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>Timestamp</th>
      <th>EventID</th>
      <th>FullyQualifiedSubjectUserName</th>
      <th>CallingStationID</th>
      <th>CalledStationID</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>505</th>
      <td>2026-05-12 05:11:57.581541+00:00</td>
      <td>6272</td>
      <td>global-tek.local/Users/svc_backup</td>
      <td>216.128.153.60</td>
      <td>172.31.17.190</td>
    </tr>
  </tbody>
</table>
</div>



### Question 2 — Attacker's Remote IP Address

What remote IP address did the attacker use to connect to the target machine?

**Investigation focus:** Examine the `CallingStationID` field in the successful NPS authentication event (`Event ID 6272`) for `svc_backup`.


```python
# Identify successful NPS authentication
df_security[
    (df_security["EventID"] == "6272") &
    (df_security["FullyQualifiedSubjectUserName"].str.contains("svc_backup", case=False, na=False))
][["Timestamp", "EventID","CallingStationID"]]
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>Timestamp</th>
      <th>EventID</th>
      <th>CallingStationID</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>505</th>
      <td>2026-05-12 05:11:57.581541+00:00</td>
      <td>6272</td>
      <td>216.128.153.60</td>
    </tr>
  </tbody>
</table>
</div>



### Question 3 — Assigned VPN Pool IP Address

What VPN pool IP address was assigned to the `svc_backup` session?


```python
# Identify assigned VPN pool IP
df_nps_txt[
    df_nps_txt["User-Name"].str.contains("svc_backup", case=False, na=False)
][["Timestamp", "User-Name", "Framed-IP-Address"]]
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>Timestamp</th>
      <th>User-Name</th>
      <th>Framed-IP-Address</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>3</th>
      <td>05/12/2026 05:11:37.000</td>
      <td>svc_backup</td>
      <td>10.10.10.58</td>
    </tr>
  </tbody>
</table>
</div>



### Question 4 — Successful Logon GUID

What is the unique Logon GUID associated with the `svc_backup` user's successful Type 10 logon?


```python
# Identify successful RDP logon
df_security[
    (df_security["EventID"] == "4624") &
    (df_security["TargetUserName"] == "svc_backup") &
    (df_security["LogonType"] == "10")
][["Timestamp", "TargetUserName", "LogonType", "IpAddress","LogonGuid", "TargetLogonId"]]
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>Timestamp</th>
      <th>TargetUserName</th>
      <th>LogonType</th>
      <th>IpAddress</th>
      <th>LogonGuid</th>
      <th>TargetLogonId</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>540</th>
      <td>2026-05-12 05:13:11.481781+00:00</td>
      <td>svc_backup</td>
      <td>10</td>
      <td>10.10.10.58</td>
      <td>{9d4f92d8-07cb-fde3-ae92-151f5d1e1a82}</td>
      <td>0x00000000009b3c9a</td>
    </tr>
    <tr>
      <th>541</th>
      <td>2026-05-12 05:13:11.481789+00:00</td>
      <td>svc_backup</td>
      <td>10</td>
      <td>10.10.10.58</td>
      <td>{00000000-0000-0000-0000-000000000000}</td>
      <td>0x00000000009b3cc4</td>
    </tr>
  </tbody>
</table>
</div>



### Question 5 — RDP Session ID

What Session ID was assigned to the successful RDP logon?

**Investigation focus:** Identify the RDP session event by filtering `assigned VPN pool IP`.


```python

# Display all Event ID 21 records
df_rdplocal[
    df_rdplocal["Address"] == "10.10.10.58" 
][["Timestamp", "EventID", "User", "SessionID", "Address"]]

```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>Timestamp</th>
      <th>EventID</th>
      <th>User</th>
      <th>SessionID</th>
      <th>Address</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>34</th>
      <td>2026-05-12 05:13:13.131023+00:00</td>
      <td>25</td>
      <td>GLOBALTEK\svc_backup</td>
      <td>7</td>
      <td>10.10.10.58</td>
    </tr>
    <tr>
      <th>53</th>
      <td>2026-05-12 05:33:51.360374+00:00</td>
      <td>24</td>
      <td>GLOBALTEK\svc_backup</td>
      <td>7</td>
      <td>10.10.10.58</td>
    </tr>
  </tbody>
</table>
</div>



### Question 6 — ProfileList Registry Last Write Timestamp

What is the Last Write Timestamp for the `svc_backup` user's ProfileList registry key?

**Investigation focus:** Locate the `svc_backup` profile under `Microsoft\Windows NT\CurrentVersion\ProfileList` and record its `LastWriteTimestamp`.


```python
# Identify svc_backup profile
df_software[
    df_software["ProfileImagePath"].str.contains(
        "svc_backup", case=False, na=False
    )
]
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>SID</th>
      <th>ProfileImagePath</th>
      <th>LastWriteTimestamp</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>3</th>
      <td>S-1-5-21-1355340450-508628708-815639551-1112</td>
      <td>C:\Users\svc_backup</td>
      <td>2026-05-12 05:32:27.092868</td>
    </tr>
  </tbody>
</table>
</div>
