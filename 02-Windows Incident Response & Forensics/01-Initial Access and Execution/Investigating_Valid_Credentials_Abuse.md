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
```
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
