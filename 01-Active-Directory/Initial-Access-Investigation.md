
### The Core Detection Pattern

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
    linkStyle 0,1,2,3,4,5 stroke:#8bea19,stroke-width:2px

    %% REQUEST FLOW - RED
    linkStyle 6,7,10,11,12,13 stroke:#ff1744,stroke-width:2px,stroke-dasharray:5 5

    %% RESPONSE FLOW - GREEN
    linkStyle 8,9,14,15 stroke:#8bea19,stroke-width:2px,stroke-dasharray:5 5
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
