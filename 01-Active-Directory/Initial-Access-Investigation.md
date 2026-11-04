Here is a simple flow chart:


```mermaid
graph LR;
subgraph ATTACKER["🔴 ATTACKER"]
        A["💻 Attacker / Hacker"]
    end

    subgraph PROCESS["⚙️ PROCESS"]
        P1["1. Discovery and Enumeration"]
        P2["2. Server Responds"]
        P3["3. Deploy the Web Shell"]
        P4["4. Execute Commands"]
        P5["5. Server Responds"]
    end

    subgraph SERVER["🟢 IIS WEB SERVER"]
        S1["🖥️ IIS Web Server"]
        S2["C:\inetpub\wwwroot"]
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

    style ATTACKER fill:#ffffff,stroke:#ff334d,stroke-width:2px,stroke-dasharray:5 5,color:#000000
    style PROCESS fill:#ffffff,stroke:#e6a700,stroke-width:2px,stroke-dasharray:5 5,color:#000000
    style SERVER fill:#ffffff,stroke:#7ac943,stroke-width:2px,stroke-dasharray:5 5,color:#000000
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
