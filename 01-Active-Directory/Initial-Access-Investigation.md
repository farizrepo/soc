## Initial Access

### Introduction
initial access attacks against 3 of the most common: IIS web applications, Exchange OWA, and VPN gateways
#### Normal vs Suspicious IIS Patterns

| **Pattern** | **Field** | **Normal** | **Suspicious** |
| :--- | :--- | :--- | :--- |
| Authentication volume | `c_ip`, `sc_status` | A few login events per user throughout the day | Hundreds of login attempts from the same IP in minutes |
| Request timing | `c_ip` | 09:15 login from 10.5.10.x (office subnet, business hours) | 03:22 login from 10.99.50.x (unknown subnet, outside hours) |
| URI paths | `cs_uri_stem` | `/owa/`, `/ecp/`, `/internalapp/default.aspx` | `/aspnet_client/system_web/shell.aspx` or `/uploads/cmd.aspx` |
| Query strings | `cs_uri_query` | `?ViewAction=ReadMessage&ItemID=AAM` | `?cmd=whoami` or `?exec=ipconfig` |
| HTTP methods | `cs_method`, `cs_uri_stem` | GET for pages, POST for login forms | POST to `/aspnet_client/shell.aspx` (a static file directory) |
| HTTP status codes | `sc_status`, `c_ip` | Occasional 404s from typos | Hundreds of 404s from a single IP in minutes (directory scanning) |

###  Web Shell Attack
#### Mitre Attack Mapping
| Behavior | Tactic | Technique ID & Name |
| --- | --- | --- |
| Exploiting the IIS application to gain access | Initial Access | T1190: Exploit Public-Facing Application |
| w3wp.exe spawning cmd.exe/powershell.exe to run commands | Execution | T1059: Command and Scripting Interpreter |
| Deploying the .aspx web shell for persistent access | Persistence | T1505.003: Server Software Component: Web Shell |


```mermaid
graph LR;
subgraph ATTACKER["🔴 ATTACKER"]
        A["💻 Attacker / Hacker"]
    end

    subgraph PROCESS["⚙️ PROCESS"]
        P1["1. Discovery and Enumeration"]
        P2["2. Server Responds<br/>/admin → 404<br/>/backup → 404<br/>/internalapp/ → 301<br/>/internalapp/upload.aspx → 200"]
        P3["3. Deploy the Web Shell"]
        P4["4. Execute Commands"]
        P5["5. Server Responds"]
    end

    subgraph SERVER["🟢 IIS WEB SERVER"]
        S1["🖥️ IIS Web Server"]
        S2["C:/inetpub/wwwroot/"]
        S3["web.config"]
        S4["/images/"]
        S5["/scripts/"]
        S6["/internalapp/"]
        S7["upload.aspx"]

        S1 --> S2
        S2 --> S3
        S2 --> S4
        S2 --> S5
        S2 --> S6
        S6 --> S7
    end

    A --> P1
    P1 --> S1
    S1 --> P2
    P2 --> A
    A --> P3
    P3 --> S1
    A --> P4
    P4 --> S1
    S1 --> P5
    P5 --> A

    %% BOX COLORS
    style ATTACKER fill:#ffffff,stroke:#ff334d,stroke-width:2px,color:#000
    style PROCESS fill:#ffffff,stroke:#e6a700,stroke-width:2px,color:#000
    style SERVER fill:#ffffff,stroke:#7ac943,stroke-width:2px,color:#000

    %% NODE COLORS
    style A fill:#263b63,color:#ffffff,stroke:#263b63
    style P1 fill:#fff3cd,color:#222,stroke:#e6a700
    style P2 fill:#263b63,color:#ffcc00,stroke:#263b63
    style P3 fill:#263b63,color:#ff334d,stroke:#263b63
    style P4 fill:#263b63,color:#ff334d,stroke:#263b63
    style P5 fill:#263b63,color:#7ac943,stroke:#263b63

    style S1 fill:#d9ecff,color:#222,stroke:#168bd2
    style S2 fill:#263b63,color:#7ac943,stroke:#7ac943
    style S3 fill:#e8f5e9,color:#222,stroke:#7ac943
    style S4 fill:#e8f5e9,color:#222,stroke:#7ac943
    style S5 fill:#e8f5e9,color:#222,stroke:#7ac943
    style S6 fill:#e8f5e9,color:#222,stroke:#7ac943
    style S7 fill:#ffe5e5,color:#d00,stroke:#ff334d

 %% DIRECTORY TREE - GREEN
    linkStyle 0,1,2,3,4,5,8,9,14,15 stroke:#8bea19,stroke-width:2.5px

    %% REQUEST FLOW - RED
    linkStyle 6,7,10,11,12,13 stroke:#ff1744,stroke-width:2.5px
```

#### Detection & Investigation
```
index=iis sc_status=404
| bin _time span=1m
| stats count AS error_count, dc(cs_uri_stem) AS unique_uris BY _time, c_ip
| where error_count > 30 AND unique_uris > 20
| sort - error_count
```
[<img width="1468" height="71" alt="image" src="https://github.com/user-attachments/assets/61d55add-553e-42b3-9fee-29cabefb593d" />](https://github.com/farizrepo/soc/blob/ad0017818337dd5c703cf26a9a9cd9f3c18c7084/source/1.%20finding%20ip.png)

```mermaid
graph LR;

    subgraph MAIN["PROCESS BEHAVIOR ANALYSIS"]
        direction LR

        subgraph MALICIOUS["🔴 MALICIOUS"]
            direction TB
            C["w3wp.exe"]
            D["cmd.exe"]
            E["whoami.exe"]
            F["net.exe"]
            G["ipconfig.exe"]

            C --> D
            D --> E
            D --> F
            D --> G
        end

        subgraph LEGITIMATE["🟢 LEGITIMATE"]
            direction TB
            A["w3wp.exe"]
            B["No child processes"]

            A --> B
        end
    end

    style MAIN fill:#ffffff,color:#1b2b46,stroke:#1b2b46,stroke-width:2px

    style C fill:#1b2b46,color:#9bea20,stroke:#1b2b46,stroke-width:2px
    style D fill:#1b2b46,color:#ff1744,stroke:#1b2b46,stroke-width:2px
    style E fill:#1b2b46,color:#ff1744,stroke:#1b2b46,stroke-width:2px
    style F fill:#1b2b46,color:#ff1744,stroke:#1b2b46,stroke-width:2px
    style G fill:#1b2b46,color:#ff1744,stroke:#1b2b46,stroke-width:2px

    style A fill:#1b2b46,color:#9bea20,stroke:#1b2b46,stroke-width:2px
    style B fill:#e8f5e9,color:#7ac943,stroke:#7ac943,stroke-width:2px

    style MALICIOUS fill:#ffffff,color:#ff1744,stroke:#ff1744,stroke-width:2px,stroke-dasharray:5 5
    style LEGITIMATE fill:#ffffff,color:#7ac943,stroke:#7ac943,stroke-width:2px,stroke-dasharray:5 5

    linkStyle 0,1,2,3 stroke:#ff1744,stroke-width:2.5px
    linkStyle 4 stroke:#7ac943,stroke-width:2.5px
```


```mermaid
graph LR;
  A["💻 Attacker / Hacker"]

    subgraph DMZ["🔴 DMZ - Demilitarized Zone"]
        direction TB
        B["🌐 Web Application"]
        C["📧 Exchange Server"]
        D["🔥 VPN Gateway"]
    end

    subgraph INTERNAL["🟢 Internal Network"]
        direction TB
        E["🖥️ Domain Controller"]
        F["📁 File Server"]
        G["🗄️ SQL Server"]
        H["👨‍💻 Workstation"]
    end

    A --> B
    A --> C
    A --> D

    B --> E
    C --> E
    D --> E

    E <--> F
    E <--> G
    E <--> H

    E --> I["🚨 IMPACT: ENTIRE DOMAIN"]

    style A fill:#263b63,color:#fff,stroke:#263b63
    style B fill:#e8f5e9,stroke:#7ac943,color:#222
    style C fill:#e8f5e9,stroke:#7ac943,color:#222
    style D fill:#e8f5e9,stroke:#7ac943,color:#222
    style E fill:#d9ecff,stroke:#168bd2,color:#222
    style F fill:#e8f5e9,stroke:#7ac943,color:#222
    style G fill:#e8f5e9,stroke:#7ac943,color:#222
    style H fill:#e8f5e9,stroke:#7ac943,color:#222
    style I fill:#ffe5e5,stroke:#ff334d,color:#d00,stroke-width:3px

    style DMZ fill:#fff,color:#000000,stroke:#ff334d,stroke-width:2px,stroke-dasharray:5 5
    style INTERNAL fill:#fff,color:#000000,stroke:#7ac943,stroke-width:2px,stroke-dasharray:5 5

    linkStyle 0,1,2,3,4,5 stroke:#ff3333,stroke-width:2.5px
    linkStyle 6,7,8,9 stroke:#22aa55,stroke-width:2.5px
