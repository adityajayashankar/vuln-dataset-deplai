"""
stack_profiles.py
─────────────────────────────────────────────────────────────────────────────
Technology stack profiles used by build_cooccurrence_v2.py and
generate_cooccurrence_pairs.py.

Each profile defines:
  - indicators:       keywords that identify this stack in a finding
  - high_confidence:  CVEs almost always present when stack is confirmed
  - conditional:      CVEs present only when sub-condition is met
  - negative_rules:   conditions under which certain CVEs are ABSENT
  - remediation_ties: groups of CVEs that share a single fix (patch one = patch all)
  - attack_chains:    ordered lists representing "step 1 → step 2 → step 3" attack paths
"""

STACK_PROFILES = {

    # ──────────────────────────────────────────────────────────────────────
    # Java Enterprise
    # ──────────────────────────────────────────────────────────────────────

    "java_log4j": {
        "display_name": "Apache Log4j (Java Logging)",
        "indicators":   ["log4j", "log4j2", "log4j-core"],
        "version_field": "log4j-core",
        "high_confidence": [
            {"cve": "CVE-2021-44228", "reason": "Log4Shell — JNDI lookup via any logged string"},
            {"cve": "CVE-2021-45046", "reason": "Log4Shell bypass — thread context patterns"},
            {"cve": "CVE-2021-45105", "reason": "DoS via infinite recursion in lookup"},
        ],
        "conditional": {
            "if_version_lt_2_17_1": [
                {"cve": "CVE-2021-44832", "reason": "Attacker-controlled JDBC config RCE"},
            ],
            "if_version_lt_2_3_1_java8": [
                {"cve": "CVE-2021-44228", "reason": "Java 8 older patch incomplete"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "log4j_version >= 2.17.1 AND formatMsgNoLookups=true",
                "absent_cves": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                "still_assess": ["CVE-2021-44832"],
                "reason":      "JNDI lookups disabled — core attack vector removed",
            },
            {
                "condition":   "log4j_version >= 2.17.1",
                "absent_cves": ["CVE-2021-44228", "CVE-2021-45046"],
                "reason":      "Official patch addresses JNDI injection root cause",
            },
        ],
        "remediation_ties": [
            {
                "fix":  "Upgrade log4j-core to ≥ 2.17.1",
                "cves": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
            }
        ],
        "attack_chains": [
            ["CVE-2021-44228", "CVE-2021-44832"],  # Initial access → config control
        ],
        "independent_assess": [
            "CVE-2022-22965",  # Spring4Shell — different component
            "CVE-2022-21449",  # Psychic Signatures — JDK level
        ],
    },

    "java_spring": {
        "display_name": "Spring Framework (Java)",
        "indicators":   ["spring", "spring-boot", "spring-framework", "springmvc"],
        "high_confidence": [
            {"cve": "CVE-2022-22965", "reason": "Spring4Shell — RCE via data binding on JDK9+"},
        ],
        "conditional": {
            "if_spring_cloud_function": [
                {"cve": "CVE-2022-22963", "reason": "SpEL injection via routing expression"},
            ],
            "if_spring_security_lt_5_6_5": [
                {"cve": "CVE-2022-22978", "reason": "Auth bypass via regex in Spring Security"},
            ],
            "if_spring_data_lt_2_6_4": [
                {"cve": "CVE-2022-22980", "reason": "SpEL injection in Spring Data MongoDB"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "JDK_version < 9 AND spring_version >= 5.3.18",
                "absent_cves": ["CVE-2022-22965"],
                "reason":      "Spring4Shell requires JDK9+ class loader module access",
            },
            {
                "condition":   "spring_version >= 5.3.18",
                "absent_cves": ["CVE-2022-22965"],
                "reason":      "Patched spring-beans version",
            },
        ],
        "remediation_ties": [
            {
                "fix":  "Upgrade spring-framework to ≥ 5.3.18 / 5.2.20",
                "cves": ["CVE-2022-22965"],
            }
        ],
        "attack_chains": [
            ["CVE-2022-22965", "CVE-2022-22963"],
        ],
    },

    "java_struts": {
        "display_name": "Apache Struts 2",
        "indicators":   ["struts2", "struts-2", "struts", "ognl"],
        "high_confidence": [
            {"cve": "CVE-2017-5638",  "reason": "Content-Type OGNL injection — Equifax breach"},
            {"cve": "CVE-2018-11776", "reason": "Namespace OGNL injection — no param required"},
            {"cve": "CVE-2019-0230",  "reason": "Forced double OGNL evaluation"},
        ],
        "conditional": {
            "if_struts_lt_2_3_35": [
                {"cve": "CVE-2017-9805",  "reason": "REST plugin XStream deserialization"},
                {"cve": "CVE-2017-12611", "reason": "Freemarker tag OGNL injection"},
            ],
            "if_struts_lt_2_5_22": [
                {"cve": "CVE-2019-0230", "reason": "Double OGNL evaluation in tag attributes"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "struts_version >= 2.5.30",
                "absent_cves": ["CVE-2017-5638", "CVE-2018-11776", "CVE-2019-0230"],
                "reason":      "All known OGNL injection vectors patched in 2.5.30+",
            },
        ],
        "remediation_ties": [
            {"fix": "Upgrade Struts2 to ≥ 2.5.30", "cves": ["CVE-2017-5638", "CVE-2018-11776", "CVE-2019-0230"]},
        ],
        "attack_chains": [
            ["CVE-2017-5638", "CVE-2017-9805"],
        ],
    },

    "java_weblogic": {
        "display_name": "Oracle WebLogic Server",
        "indicators":   ["weblogic", "wls", "t3://"],
        "high_confidence": [
            {"cve": "CVE-2019-2725",  "reason": "Deserialization via _async servlets — no auth"},
            {"cve": "CVE-2020-14882", "reason": "Auth bypass + RCE in console component"},
            {"cve": "CVE-2021-2109",  "reason": "JNDI injection via admin console"},
            {"cve": "CVE-2023-21839", "reason": "IIOP/T3 deserialization — no auth required"},
        ],
        "conditional": {
            "if_t3_port_open": [
                {"cve": "CVE-2018-2628",  "reason": "T3 protocol deserialization"},
                {"cve": "CVE-2018-2893",  "reason": "T3 protocol bypass after 2628 patch"},
            ],
            "if_iiop_enabled": [
                {"cve": "CVE-2023-21839", "reason": "IIOP deserialization — separate attack surface"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "T3_protocol_blocked_at_firewall",
                "absent_cves": ["CVE-2018-2628", "CVE-2018-2893"],
                "still_assess": ["CVE-2020-14882"],
                "reason":      "T3 CVEs require network access to T3 port (7001/7002)",
            },
        ],
        "remediation_ties": [
            {"fix": "Apply Oracle CPU October 2023", "cves": ["CVE-2023-21839"]},
            {"fix": "Apply Oracle CPU October 2020", "cves": ["CVE-2020-14882"]},
        ],
        "attack_chains": [
            ["CVE-2020-14882", "CVE-2021-2109"],
        ],
    },

    "java_shiro": {
        "display_name": "Apache Shiro (Java auth framework)",
        "indicators":   ["shiro", "rememberme", "apache-shiro"],
        "high_confidence": [
            {"cve": "CVE-2016-4437", "reason": "RememberMe cookie AES deserialization"},
            {"cve": "CVE-2019-12422", "reason": "RememberMe padding oracle"},
            {"cve": "CVE-2020-1957",  "reason": "Auth bypass via path traversal"},
        ],
        "conditional": {
            "if_shiro_lt_1_7_1": [
                {"cve": "CVE-2020-17523", "reason": "Auth bypass via empty string URL"},
                {"cve": "CVE-2020-13933", "reason": "Auth bypass special character"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "shiro_version >= 1.10.0 AND custom_key_configured",
                "absent_cves": ["CVE-2016-4437"],
                "reason":      "1.10.0 defaults to GCM; custom key removes default-key attack vector",
            },
        ],
        "attack_chains": [
            ["CVE-2016-4437", "CVE-2020-1957"],  # Deserialization → auth bypass pivot
        ],
    },

    "java_jenkins": {
        "display_name": "Jenkins CI/CD",
        "indicators":   ["jenkins", "jenkins-ci", "hudson"],
        "high_confidence": [
            {"cve": "CVE-2018-1000861", "reason": "Stapler routing bypass → RCE"},
            {"cve": "CVE-2019-1003000", "reason": "Script security sandbox bypass"},
            {"cve": "CVE-2024-23897",   "reason": "Arbitrary file read via args4j"},
        ],
        "conditional": {
            "if_script_console_enabled": [
                {"cve": "CVE-2019-1003000", "reason": "Groovy sandbox bypass via Pipeline"},
            ],
            "if_jenkins_lt_2_441": [
                {"cve": "CVE-2024-23897", "reason": "CLI file read — critical in 2024 wave"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "jenkins_version >= 2.441 AND LTS_version >= 2.426.3",
                "absent_cves": ["CVE-2024-23897"],
                "reason":      "Patched in Jenkins 2.441 — args4j expansion disabled",
            },
        ],
        "attack_chains": [
            ["CVE-2024-23897", "CVE-2019-1003000"],
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # PHP / CMS
    # ──────────────────────────────────────────────────────────────────────

    "php_drupal": {
        "display_name": "Drupal CMS (PHP)",
        "indicators":   ["drupal", "drupal-core", "drupal8", "drupal7"],
        "high_confidence": [
            {"cve": "CVE-2018-7600", "reason": "Drupalgeddon2 — remote code execution"},
            {"cve": "CVE-2018-7602", "reason": "Drupalgeddon3 — authenticated follow-on RCE"},
        ],
        "conditional": {
            "if_drupal_7": [
                {"cve": "CVE-2014-3704", "reason": "Drupageddon1 — SQLi via DB layer"},
            ],
            "if_drupal_8_lt_8_5": [
                {"cve": "CVE-2018-7600", "reason": "Unpatched Drupal 8.x < 8.5.1"},
            ],
            "if_image_module_enabled": [
                {"cve": "CVE-2019-6339", "reason": "ImageMagick RCE via phar deserialization"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "drupal_version >= 9.5.3 OR drupal_version >= 10.0.3",
                "absent_cves": ["CVE-2018-7600", "CVE-2018-7602"],
                "reason":      "Drupalgeddon patches applied in 8.5.1/9.x+",
            },
        ],
        "remediation_ties": [
            {"fix": "Drupal security update SA-CORE-2018-002", "cves": ["CVE-2018-7600"]},
            {"fix": "Drupal security update SA-CORE-2018-004", "cves": ["CVE-2018-7602"]},
        ],
        "attack_chains": [
            ["CVE-2014-3704", "CVE-2018-7600", "CVE-2018-7602"],
        ],
    },

    "php_phpunit": {
        "display_name": "PHPUnit (Dev/Testing dependency)",
        "indicators":   ["phpunit", "vendor/phpunit"],
        "high_confidence": [
            {"cve": "CVE-2017-9841", "reason": "eval() injection via /vendor/phpunit in production"},
        ],
        "negative_rules": [
            {
                "condition":   "vendor_directory_not_web_accessible",
                "absent_cves": ["CVE-2017-9841"],
                "reason":      "Exploit requires HTTP access to /vendor/ — blocked by webroot config",
            },
            {
                "condition":   "phpunit_not_installed_in_production",
                "absent_cves": ["CVE-2017-9841"],
                "reason":      "Dev dependency absent from production deployment",
            },
        ],
        "attack_chains": [],
    },

    "php_laravel": {
        "display_name": "Laravel PHP Framework",
        "indicators":   ["laravel", "artisan", ".env laravel"],
        "high_confidence": [
            {"cve": "CVE-2021-3129", "reason": "Debug mode RCE via Ignition facade"},
        ],
        "conditional": {
            "if_debug_mode_on": [
                {"cve": "CVE-2021-3129", "reason": "APP_DEBUG=true exposes Ignition endpoint"},
            ],
            "if_env_file_exposed": [
                {"cve": "CVE-2017-16894", "reason": ".env disclosure — credential exposure"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "APP_DEBUG=false AND ignition_version >= 2.5.2",
                "absent_cves": ["CVE-2021-3129"],
                "reason":      "Debug mode off — Ignition endpoint not exposed; patched version",
            },
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # Microsoft / Windows
    # ──────────────────────────────────────────────────────────────────────

    "microsoft_exchange": {
        "display_name": "Microsoft Exchange Server",
        "indicators":   ["exchange", "owa", "autodiscover", "msexchange"],
        "high_confidence": [
            {"cve": "CVE-2021-26855", "reason": "ProxyLogon — SSRF auth bypass"},
            {"cve": "CVE-2021-26857", "reason": "ProxyLogon — deserialization after bypass"},
            {"cve": "CVE-2021-26858", "reason": "ProxyLogon — arbitrary file write post-auth"},
            {"cve": "CVE-2021-27065", "reason": "ProxyLogon — arbitrary file write post-auth"},
        ],
        "conditional": {
            "if_exchange_2016_or_2019": [
                {"cve": "CVE-2021-34473", "reason": "ProxyShell — path confusion bypass"},
                {"cve": "CVE-2021-34523", "reason": "ProxyShell — elevation of privilege"},
                {"cve": "CVE-2021-31207", "reason": "ProxyShell — mailbox import RCE"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "exchange_version >= 15.2.986.15",
                "absent_cves": ["CVE-2021-26855", "CVE-2021-26857"],
                "reason":      "ProxyLogon patch applied — March 2021 SU or later",
            },
        ],
        "remediation_ties": [
            {
                "fix":  "March 2021 Exchange Security Update",
                "cves": ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"],
            },
            {
                "fix":  "May 2021 Exchange Security Update (ProxyShell)",
                "cves": ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
            },
        ],
        "attack_chains": [
            # ProxyLogon chain
            ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858"],
            # ProxyShell chain
            ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
        ],
    },

    "microsoft_windows_ad": {
        "display_name": "Windows Active Directory / Domain Services",
        "indicators":   ["active directory", "kerberos", "ldap", "domain controller", "ad ds"],
        "high_confidence": [
            {"cve": "CVE-2020-1472",  "reason": "Zerologon — instant DC compromise via Netlogon"},
            {"cve": "CVE-2021-42278", "reason": "sAMAccountName spoofing for privilege escalation"},
            {"cve": "CVE-2021-42287", "reason": "noPac — combined with 42278 for DA"},
        ],
        "conditional": {
            "if_smb_exposed": [
                {"cve": "CVE-2017-0144", "reason": "EternalBlue — SMBv1 RCE (WannaCry vector)"},
                {"cve": "CVE-2020-0796", "reason": "SMBGhost — SMBv3 compression buffer overflow"},
            ],
            "if_print_spooler_running": [
                {"cve": "CVE-2021-34527", "reason": "PrintNightmare — print spooler RCE"},
                {"cve": "CVE-2021-1675",  "reason": "PrintNightmare variant — LPE + RCE"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "SMBv1_disabled AND patch_MS17-010_applied",
                "absent_cves": ["CVE-2017-0144"],
                "reason":      "EternalBlue requires SMBv1; disabled + patched = not exploitable",
            },
            {
                "condition":   "print_spooler_service_disabled",
                "absent_cves": ["CVE-2021-34527", "CVE-2021-1675"],
                "reason":      "PrintNightmare requires Spooler service running",
            },
            {
                "condition":   "netlogon_secure_channel_enforced_via_gpo",
                "absent_cves": ["CVE-2020-1472"],
                "reason":      "Zerologon blocked by enforcement mode (FullSecureChannelProtection=1)",
            },
        ],
        "remediation_ties": [
            {"fix": "KB5008380 + enforcement mode GPO", "cves": ["CVE-2021-42278", "CVE-2021-42287"]},
            {"fix": "Disable print spooler on DCs",      "cves": ["CVE-2021-34527", "CVE-2021-1675"]},
        ],
        "attack_chains": [
            ["CVE-2020-1472", "CVE-2021-42278", "CVE-2021-42287"],  # Zerologon → noPac
            ["CVE-2017-0144", "CVE-2020-1472"],                      # EternalBlue → Zerologon
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # Network / Infra
    # ──────────────────────────────────────────────────────────────────────

    "network_fortinet": {
        "display_name": "Fortinet (FortiGate / FortiOS)",
        "indicators":   ["fortinet", "fortigate", "fortios", "forticlient"],
        "high_confidence": [
            {"cve": "CVE-2018-13379", "reason": "FortiOS SSL VPN path traversal — credential read"},
            {"cve": "CVE-2019-11510", "reason": "Pulse Secure (often paired with Fortinet infra)"},
            {"cve": "CVE-2022-40684", "reason": "FortiOS/FortiProxy auth bypass — config write"},
            {"cve": "CVE-2023-27997", "reason": "FortiOS SSL VPN heap overflow pre-auth RCE"},
        ],
        "conditional": {
            "if_fortios_lt_7_2_5": [
                {"cve": "CVE-2023-27997", "reason": "XORtigate — unpatched SSL VPN heap overflow"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "ssl_vpn_webmode_disabled",
                "absent_cves": ["CVE-2018-13379", "CVE-2023-27997"],
                "reason":      "SSL VPN web mode disabled — HTTP endpoint not exposed",
            },
        ],
        "attack_chains": [
            ["CVE-2018-13379", "CVE-2022-40684"],  # Cred harvest → config takeover
        ],
    },

    "network_cisco": {
        "display_name": "Cisco IOS / IOS XE / ASA",
        "indicators":   ["cisco", "ios xe", "ios-xe", "cisco asa", "webui cisco"],
        "high_confidence": [
            {"cve": "CVE-2023-20198", "reason": "IOS XE WebUI auth bypass — creates root user"},
            {"cve": "CVE-2023-20273", "reason": "IOS XE command injection — follows 20198"},
            {"cve": "CVE-2018-0171",  "reason": "Smart Install RCE — no auth"},
        ],
        "conditional": {
            "if_web_ui_enabled": [
                {"cve": "CVE-2023-20198", "reason": "WebUI must be reachable (ip http server)"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "ip_http_server_disabled AND ip_http_secure_server_disabled",
                "absent_cves": ["CVE-2023-20198", "CVE-2023-20273"],
                "reason":      "WebUI access disabled at IOS level — attack surface removed",
            },
        ],
        "remediation_ties": [
            {
                "fix":  "Apply Cisco advisory cisco-sa-iosxe-webui-privesc-j22SaA4z",
                "cves": ["CVE-2023-20198", "CVE-2023-20273"],
            },
        ],
        "attack_chains": [
            ["CVE-2023-20198", "CVE-2023-20273"],
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # Middleware / Message Brokers
    # ──────────────────────────────────────────────────────────────────────

    "middleware_activemq": {
        "display_name": "Apache ActiveMQ",
        "indicators":   ["activemq", "active-mq", "activemq broker"],
        "high_confidence": [
            {"cve": "CVE-2023-46604", "reason": "ClassInfo deserialization RCE — ExceptionResponse"},
            {"cve": "CVE-2022-41678", "reason": "Jolokia/API RCE via JMX"},
            {"cve": "CVE-2016-3088",  "reason": "Fileserver upload arbitrary file write"},
        ],
        "negative_rules": [
            {
                "condition":   "activemq_version >= 5.15.16 AND version >= 5.16.7",
                "absent_cves": ["CVE-2023-46604"],
                "reason":      "CVE-2023-46604 patched in ActiveMQ 5.15.16 / 5.16.7",
            },
            {
                "condition":   "fileserver_servlet_disabled",
                "absent_cves": ["CVE-2016-3088"],
                "reason":      "Fileserver disabled in activemq.xml — upload vector removed",
            },
        ],
        "attack_chains": [
            ["CVE-2016-3088", "CVE-2022-41678"],
        ],
    },

    "middleware_redis": {
        "display_name": "Redis (in-memory data store)",
        "indicators":   ["redis", "redis-server", ":6379"],
        "high_confidence": [
            {"cve": "CVE-2022-0543",  "reason": "Lua sandbox escape on Debian-packaged Redis"},
        ],
        "conditional": {
            "if_no_auth_required": [
                {"cve": "CVE-2015-4335", "reason": "Unauthenticated eval() code execution"},
            ],
            "if_redis_lt_7_0": [
                {"cve": "CVE-2022-24736", "reason": "SRANDMEMBER crash / potential memory disclosure"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "requirepass_set AND bind_127_0_0_1",
                "absent_cves": ["CVE-2015-4335"],
                "reason":      "Auth required + loopback bind — no remote unauthenticated access",
            },
        ],
        "attack_chains": [],
    },

    # ──────────────────────────────────────────────────────────────────────
    # Confluence / Atlassian
    # ──────────────────────────────────────────────────────────────────────

    "atlassian_confluence": {
        "display_name": "Atlassian Confluence",
        "indicators":   ["confluence", "atlassian confluence", "confluence server"],
        "high_confidence": [
            {"cve": "CVE-2022-26134", "reason": "OGNL injection — no auth required"},
            {"cve": "CVE-2021-26084", "reason": "OGNL injection — pre-auth RCE"},
            {"cve": "CVE-2023-22527", "reason": "Template injection RCE — Confluence Data Center"},
        ],
        "conditional": {
            "if_confluence_lt_7_4_17": [
                {"cve": "CVE-2021-26084", "reason": "Unpatched pre-7.4.17 — exploitable pre-auth"},
            ],
            "if_confluence_data_center": [
                {"cve": "CVE-2023-22527", "reason": "Data Center specific template injection"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "confluence_version >= 7.19.16",
                "absent_cves": ["CVE-2022-26134"],
                "reason":      "Patched in 7.19.16 LTS — OGNL injection blocked",
            },
        ],
        "attack_chains": [
            ["CVE-2022-26134", "CVE-2023-22527"],
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # DevOps / Source Control
    # ──────────────────────────────────────────────────────────────────────

    "devops_gitlab": {
        "display_name": "GitLab CE/EE",
        "indicators":   ["gitlab", "gitlab-ce", "gitlab-ee"],
        "high_confidence": [
            {"cve": "CVE-2021-22205", "reason": "ExifTool RCE via image upload — no auth"},
            {"cve": "CVE-2023-7028",  "reason": "Account takeover via password reset"},
        ],
        "conditional": {
            "if_gitlab_lt_13_10_3": [
                {"cve": "CVE-2021-22205", "reason": "Unpatched — ExifTool 7.04 bundled"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "gitlab_version >= 16.7.2",
                "absent_cves": ["CVE-2023-7028"],
                "reason":      "Password reset bypass patched in 16.7.2",
            },
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # Cloud / Container
    # ──────────────────────────────────────────────────────────────────────

    "cloud_kubernetes": {
        "display_name": "Kubernetes (container orchestration)",
        "indicators":   ["kubernetes", "kubectl", "k8s", "kubelet", "kube-apiserver"],
        "high_confidence": [
            {"cve": "CVE-2018-1002105", "reason": "API server request proxy privesc"},
            {"cve": "CVE-2019-11247",   "reason": "API server path confusion — cluster-scope access"},
            {"cve": "CVE-2022-3294",    "reason": "Node address bypasses — Kubelet auth bypass"},
        ],
        "conditional": {
            "if_anonymous_auth_enabled": [
                {"cve": "CVE-2019-11248", "reason": "/debug/pprof exposed without auth"},
            ],
            "if_etcd_exposed_no_auth": [
                {"cve": "CVE-2020-15106", "reason": "etcd raft panic — DoS"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "anonymous_auth_disabled AND RBAC_enforced",
                "absent_cves": ["CVE-2019-11248"],
                "reason":      "Debug endpoint requires auth when anonymous disabled",
            },
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # Database
    # ──────────────────────────────────────────────────────────────────────

    "db_elasticsearch": {
        "display_name": "Elasticsearch",
        "indicators":   ["elasticsearch", "kibana", ":9200", "elastic stack"],
        "high_confidence": [
            {"cve": "CVE-2014-3120", "reason": "Dynamic scripting RCE — no auth"},
            {"cve": "CVE-2015-1427", "reason": "Groovy sandbox escape RCE"},
            {"cve": "CVE-2015-3337", "reason": "Directory traversal via site plugins"},
        ],
        "conditional": {
            "if_no_xpack_security": [
                {"cve": "CVE-2015-5531", "reason": "Snapshot restore path traversal"},
            ],
            "if_elasticsearch_lt_6_8_1": [
                {"cve": "CVE-2019-7614", "reason": "Response injection via log4j logger"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "dynamic_scripting_disabled AND es_version >= 1_6_0",
                "absent_cves": ["CVE-2014-3120", "CVE-2015-1427"],
                "reason":      "Dynamic scripting disabled by default in ES 1.6+ — root cause removed",
            },
            {
                "condition":   "xpack_security_enabled AND tls_configured",
                "absent_cves": ["CVE-2015-5531"],
                "reason":      "X-Pack security layer enforces auth on snapshot API",
            },
        ],
        "attack_chains": [
            ["CVE-2014-3120", "CVE-2015-1427"],
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # AI / ML Tooling (emerging stack)
    # ──────────────────────────────────────────────────────────────────────

    "ai_comfyui_gradio": {
        "display_name": "AI Tooling (ComfyUI / Gradio / Ollama)",
        "indicators":   ["comfyui", "gradio", "ollama", "stable diffusion", "automatic1111"],
        "high_confidence": [
            {"cve": "CVE-2025-67303", "reason": "ComfyUI SSRF + path traversal"},
            {"cve": "CVE-2023-51449", "reason": "Gradio auth bypass path traversal"},
        ],
        "conditional": {
            "if_public_facing": [
                {"cve": "CVE-2025-67303", "reason": "SSRF exploitable when ComfyUI internet-exposed"},
            ],
        },
        "negative_rules": [
            {
                "condition":   "gradio_version >= 4.11.0",
                "absent_cves": ["CVE-2023-51449"],
                "reason":      "Path traversal patched in Gradio 4.11.0",
            },
        ],
        "attack_chains": [],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers for downstream consumers
# ─────────────────────────────────────────────────────────────────────────────

def get_all_cves_in_profiles():
    """Returns set of all CVE IDs mentioned across all profiles."""
    cves = set()
    for profile in STACK_PROFILES.values():
        for item in profile.get("high_confidence", []):
            cves.add(item["cve"])
        for items in profile.get("conditional", {}).values():
            for item in items:
                cves.add(item["cve"])
        for rule in profile.get("negative_rules", []):
            cves.update(rule.get("absent_cves", []))
            cves.update(rule.get("still_assess", []))
        for group in profile.get("remediation_ties", []):
            cves.update(group.get("cves", []))
        for chain in profile.get("attack_chains", []):
            cves.update(chain)
        cves.update(profile.get("independent_assess", []))
    return cves


def get_profile_for_cve(cve_id):
    """Returns list of profile keys that mention a given CVE."""
    results = []
    for key, profile in STACK_PROFILES.items():
        all_cves = set()
        for item in profile.get("high_confidence", []):
            all_cves.add(item["cve"])
        for items in profile.get("conditional", {}).values():
            for item in items:
                all_cves.add(item["cve"])
        if cve_id in all_cves:
            results.append(key)
    return results


if __name__ == "__main__":
    all_cves = get_all_cves_in_profiles()
    print(f"Stack profiles defined: {len(STACK_PROFILES)}")
    print(f"Total CVEs referenced:  {len(all_cves)}")
    for k, v in STACK_PROFILES.items():
        chains = v.get("attack_chains", [])
        print(f"  {k:35s}  high_conf={len(v.get('high_confidence',[]))}  chains={len(chains)}")