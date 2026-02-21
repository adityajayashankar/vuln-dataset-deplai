attack_keywords = {
    "T1190": {
        "tactic": "Initial Access",
        "keywords": ["sql injection", "xss", "remote code execution", "rce"]
    },
    "T1059": {
        "tactic": "Execution",
        "keywords": ["powershell", "cmd.exe", "bash", "shell execution"]
    },
    "T1078": {
        "tactic": "Persistence",
        "keywords": ["credential reuse", "default credentials", "hardcoded password"]
    },
    "T1003": {
        "tactic": "Credential Access",
        "keywords": ["credential dumping", "lsass"]
    },
    "T1046": {
        "tactic": "Discovery",
        "keywords": ["port scan", "network scan"]
    },
    "T1499": {
        "tactic": "Impact",
        "keywords": ["denial of service", "dos"]
    }
}