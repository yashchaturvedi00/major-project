"""
Attack Response Training — Scenario Engine.
Generates training scenarios with realistic logs, response options, and MITRE ATT&CK context.
"""
import random

SCENARIOS = [
    {
        "scenario_id": "SC-001",
        "attack_type": "Brute Force",
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "tactic": "Credential Access",
        "kill_chain_stage": 8,
        "severity": "High",
        "description": "Multiple failed login attempts detected from a single IP address targeting the SSH service. The attacker is systematically trying common username/password combinations at a rate of 50+ attempts per minute, indicating an automated brute force tool.",
        "realistic_logs": """[2026-05-09 14:23:01] sshd[2841]: Failed password for root from 185.220.101.42 port 48832
[2026-05-09 14:23:01] sshd[2841]: Failed password for admin from 185.220.101.42 port 48833
[2026-05-09 14:23:02] sshd[2843]: Failed password for root from 185.220.101.42 port 48834
[2026-05-09 14:23:02] sshd[2844]: Failed password for ubuntu from 185.220.101.42 port 48835
[2026-05-09 14:23:03] sshd[2845]: Failed password for test from 185.220.101.42 port 48836
[2026-05-09 14:23:03] sshd[2846]: Failed password for admin from 185.220.101.42 port 48837
[2026-05-09 14:23:04] sshd[2847]: Failed password for root from 185.220.101.42 port 48838
[WARNING] 847 failed login attempts in last 15 minutes from 185.220.101.42""",
        "options": [
            {"id": "A", "text": "Block the IP address at the firewall immediately", "is_correct": True,
             "explanation": "Correct! Blocking the offending IP stops the brute force attack immediately while preserving system availability for legitimate users.",
             "consequences": "The attack stops instantly. No legitimate users are affected. The attacker would need to switch to a different IP to continue."},
            {"id": "B", "text": "Ignore — failed attempts are harmless", "is_correct": False,
             "explanation": "Incorrect. Ignoring brute force attacks risks eventual credential compromise. At 50+ attempts/minute, weak passwords can be cracked within hours.",
             "consequences": "If any account has a weak password, the attacker gains full SSH access, leading to potential data theft, ransomware deployment, or lateral movement."},
            {"id": "C", "text": "Restart the SSH service", "is_correct": False,
             "explanation": "Incorrect. Restarting SSH only causes a brief interruption. The attacker will resume immediately since no blocking rule was applied.",
             "consequences": "Legitimate users lose their active sessions. The attacker resumes within seconds after the service restarts, and you've gained nothing."},
            {"id": "D", "text": "Disable the firewall to investigate traffic", "is_correct": False,
             "explanation": "Incorrect. Disabling the firewall removes ALL protection, exposing every service on the machine to the internet.",
             "consequences": "All services become exposed. The attacker and others can now target any open port, dramatically increasing the attack surface."}
        ],
        "correct_response_id": "A",
        "mitigation_guidance": "1. Implement fail2ban or similar IPS to auto-block after N failures\n2. Use SSH key-based authentication instead of passwords\n3. Change SSH port from default 22\n4. Enable MFA for SSH access\n5. Use allowlists for SSH access where possible",
        "real_world_example": "The 2020 SolarWinds attackers used password spraying (a brute force variant) against cloud service accounts as one of their initial access methods."
    },
    {
        "scenario_id": "SC-002",
        "attack_type": "Phishing",
        "mitre_id": "T1566",
        "mitre_name": "Phishing",
        "tactic": "Initial Access",
        "kill_chain_stage": 3,
        "severity": "High",
        "description": "An email with a suspicious attachment was detected arriving at multiple employee mailboxes. The sender spoofs an internal HR address and urges recipients to open an attached 'salary_review.docm' file containing macros.",
        "realistic_logs": """[2026-05-09 09:15:22] mail-gw: FROM=<hr-dept@c0mpany-internal.com> TO=<john@company.com> SUBJECT="Urgent: Q2 Salary Review"
[2026-05-09 09:15:22] mail-gw: ATTACHMENT=salary_review.docm SIZE=245KB MACRO=DETECTED
[2026-05-09 09:15:23] mail-gw: SPF=FAIL DKIM=FAIL DMARC=FAIL for domain c0mpany-internal.com
[2026-05-09 09:15:23] mail-gw: X-Spam-Score: 8.5/10 BAYES_99 FORGED_SENDER MACRO_ATTACH
[2026-05-09 09:16:01] mail-gw: Same message sent to 47 recipients in last 2 minutes
[2026-05-09 09:17:30] endpoint[WS-PC-031]: ALERT macro execution blocked in salary_review.docm
[WARNING] Phishing campaign targeting 47 mailboxes with macro-enabled document""",
        "options": [
            {"id": "A", "text": "Quarantine the email and alert all employees", "is_correct": True,
             "explanation": "Correct! Quarantining removes the threat while the company-wide alert prevents anyone who received it from opening the attachment.",
             "consequences": "The phishing email is neutralized. Employees are warned and educated. Any copies already downloaded can be identified and removed."},
            {"id": "B", "text": "Delete only the attachment but deliver the email", "is_correct": False,
             "explanation": "Incorrect. The email body likely contains phishing links or social engineering that could trick users into other actions.",
             "consequences": "Users may follow links in the email body, visit spoofed login pages, or respond with sensitive information to the attacker."},
            {"id": "C", "text": "Forward the email to IT for analysis before acting", "is_correct": False,
             "explanation": "Incorrect. While analysis is valuable, delaying quarantine gives users more time to open the malicious attachment.",
             "consequences": "During the analysis delay, multiple employees may open the macro document, resulting in malware execution across workstations."},
            {"id": "D", "text": "Block the sender email address only", "is_correct": False,
             "explanation": "Incorrect. Attackers trivially change sender addresses. This doesn't address emails already delivered to 47 inboxes.",
             "consequences": "The 47 already-delivered emails remain in inboxes. The attacker sends the next wave from a different spoofed address."}
        ],
        "correct_response_id": "A",
        "mitigation_guidance": "1. Deploy email gateway with macro/attachment scanning\n2. Enforce DMARC/DKIM/SPF policies\n3. Disable macros by default in Office apps\n4. Conduct regular phishing awareness training\n5. Implement email sandboxing for attachments",
        "real_world_example": "The 2016 DNC hack began with a phishing email containing a credential-harvesting link, sent to campaign chairman John Podesta."
    },
    {
        "scenario_id": "SC-003",
        "attack_type": "Command and Scripting Interpreter",
        "mitre_id": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "kill_chain_stage": 4,
        "severity": "High",
        "description": "A PowerShell process was detected executing an obfuscated Base64-encoded command that downloads and runs a remote payload. The process was spawned from a Word document macro, suggesting a post-phishing execution chain.",
        "realistic_logs": """[2026-05-09 09:22:14] endpoint[WS-PC-031]: PROCESS_CREATE pid=5847 ppid=2341 (WINWORD.EXE)
[2026-05-09 09:22:14] endpoint[WS-PC-031]: cmd="powershell.exe -NoP -W Hidden -Enc aQBlAHgAIAAoAG4AZQB3..."
[2026-05-09 09:22:15] endpoint[WS-PC-031]: NETWORK_CONN pid=5847 dst=23.95.67.100:443 (HTTPS)
[2026-05-09 09:22:16] endpoint[WS-PC-031]: FILE_CREATE C:\\Users\\john\\AppData\\Local\\Temp\\svchost.exe
[2026-05-09 09:22:17] endpoint[WS-PC-031]: PROCESS_CREATE pid=5901 name=svchost.exe UNSIGNED
[2026-05-09 09:22:18] endpoint[WS-PC-031]: REGISTRY_MOD HKCU\\Software\\Microsoft\\Windows\\Run\\UpdateSvc
[WARNING] Suspicious execution chain: WINWORD.EXE → powershell.exe → svchost.exe (unsigned)""",
        "options": [
            {"id": "A", "text": "Isolate the endpoint from the network immediately", "is_correct": True,
             "explanation": "Correct! Network isolation contains the threat, preventing C2 communication and lateral movement while preserving forensic evidence.",
             "consequences": "The malware loses C2 connectivity. Lateral movement is blocked. The endpoint can be safely forensically analyzed and reimaged."},
            {"id": "B", "text": "Kill the PowerShell process only", "is_correct": False,
             "explanation": "Incorrect. The payload (svchost.exe) has already been dropped and is running. The registry persistence key means it will survive a reboot.",
             "consequences": "The dropped malware continues running. The persistence mechanism ensures reinfection even after killing PowerShell. C2 channel stays active."},
            {"id": "C", "text": "Run a full antivirus scan", "is_correct": False,
             "explanation": "Incorrect. While an AV scan may eventually detect the payload, it takes time. The malware is actively communicating with C2 right now.",
             "consequences": "During the scan, the malware exfiltrates data, downloads additional payloads, and potentially spreads to other machines on the network."},
            {"id": "D", "text": "Reboot the workstation", "is_correct": False,
             "explanation": "Incorrect. The attacker added a registry Run key for persistence. Rebooting will restart the malware automatically.",
             "consequences": "The malware restarts via the registry persistence key. You've lost volatile memory evidence and the attack continues uninterrupted."}
        ],
        "correct_response_id": "A",
        "mitigation_guidance": "1. Enable PowerShell Constrained Language Mode\n2. Enable Script Block Logging and Module Logging\n3. Use AppLocker or WDAC to restrict script execution\n4. Block macro execution from internet-downloaded documents\n5. Deploy EDR with behavioral detection capabilities",
        "real_world_example": "The Emotet malware used macro-enabled documents to launch obfuscated PowerShell downloaders, infecting hundreds of thousands of endpoints worldwide (2018-2021)."
    },
    {
        "scenario_id": "SC-004",
        "attack_type": "Denial of Service",
        "mitre_id": "T1499",
        "mitre_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "kill_chain_stage": 14,
        "severity": "High",
        "description": "A massive flood of SYN packets targeting port 443 has overwhelmed the web server. Connection queue is saturated, legitimate users are getting timeout errors, and CPU usage has spiked to 98%.",
        "realistic_logs": """[2026-05-09 11:45:01] fw: SYN_FLOOD detected dst=10.0.1.50:443 rate=125000 pps
[2026-05-09 11:45:02] web-srv: Connection queue full (backlog=128/128) DROPPING new connections
[2026-05-09 11:45:03] monitor: CPU=98.2% MEM=87% NET_IN=2.4 Gbps (normal: 200 Mbps)
[2026-05-09 11:45:04] fw: Top source IPs: 91.*.*.* (23%), 185.*.*.* (18%), 45.*.*.* (15%)
[2026-05-09 11:45:05] web-srv: HTTP 503 responses: 12,847 in last 60 seconds
[2026-05-09 11:45:06] lb: Health check FAILED for backend web-srv-01, web-srv-02
[CRITICAL] DDoS attack in progress — web service unavailable""",
        "options": [
            {"id": "A", "text": "Enable rate limiting and activate DDoS mitigation service", "is_correct": True,
             "explanation": "Correct! Rate limiting reduces flood impact while a DDoS mitigation service (like Cloudflare or AWS Shield) can absorb and filter the attack traffic at scale.",
             "consequences": "Attack traffic is filtered upstream. Legitimate users regain access within minutes. The mitigation service absorbs the volumetric attack."},
            {"id": "B", "text": "Block all incoming traffic at the firewall", "is_correct": False,
             "explanation": "Incorrect. Blocking ALL traffic stops the attack but also blocks every legitimate user — you've effectively completed the attacker's objective for them.",
             "consequences": "The service is now completely offline for everyone. The attacker achieved their goal of denial of service without needing to continue the attack."},
            {"id": "C", "text": "Restart the web server", "is_correct": False,
             "explanation": "Incorrect. The flood is network-level. Restarting the web server provides seconds of relief before the connection queue fills again.",
             "consequences": "Brief service restoration followed by immediate re-saturation. Active user sessions are lost. The attack continues unaffected."},
            {"id": "D", "text": "Increase server resources (scale up CPU/RAM)", "is_correct": False,
             "explanation": "Incorrect. Scaling up a single server cannot match a distributed attack generating 2.4 Gbps. The bottleneck is network capacity, not compute.",
             "consequences": "Money is spent on resources that don't address the root cause. The attack bandwidth far exceeds any single server's capacity."}
        ],
        "correct_response_id": "A",
        "mitigation_guidance": "1. Use a CDN/DDoS protection service (Cloudflare, AWS Shield)\n2. Configure SYN cookies on the server\n3. Implement rate limiting at load balancer level\n4. Set up geo-blocking for non-business regions\n5. Have a DDoS response runbook pre-approved",
        "real_world_example": "The 2016 Dyn DNS DDoS attack (Mirai botnet) took down Twitter, Netflix, Reddit, and GitHub using 1.2 Tbps of traffic from IoT devices."
    },
    {
        "scenario_id": "SC-005",
        "attack_type": "Network Service Scanning",
        "mitre_id": "T1046",
        "mitre_name": "Network Service Scanning",
        "tactic": "Discovery",
        "kill_chain_stage": 9,
        "severity": "Medium",
        "description": "An internal host is performing rapid sequential port scans against multiple servers on the network. The scanning pattern suggests an attacker or compromised machine performing reconnaissance to map available services.",
        "realistic_logs": """[2026-05-09 03:12:01] fw: SYN src=10.0.2.105 dst=10.0.1.10:22 FLAGS=S
[2026-05-09 03:12:01] fw: SYN src=10.0.2.105 dst=10.0.1.10:80 FLAGS=S
[2026-05-09 03:12:01] fw: SYN src=10.0.2.105 dst=10.0.1.10:443 FLAGS=S
[2026-05-09 03:12:02] fw: SYN src=10.0.2.105 dst=10.0.1.11:22,80,443,3389,8080
[2026-05-09 03:12:03] fw: SYN src=10.0.2.105 dst=10.0.1.12:22,80,443,3306,5432
[2026-05-09 03:12:04] fw: 2,847 connection attempts from 10.0.2.105 in 60 seconds
[2026-05-09 03:12:05] ids: NMAP_SYN_SCAN signature match from 10.0.2.105
[WARNING] Internal host 10.0.2.105 performing network reconnaissance""",
        "options": [
            {"id": "A", "text": "Isolate the scanning host and investigate for compromise", "is_correct": True,
             "explanation": "Correct! An internal host scanning the network is likely compromised. Isolating it stops reconnaissance and prevents the attacker from progressing to exploitation.",
             "consequences": "Reconnaissance stops. The compromised host is contained for forensic analysis. The attacker loses their foothold and cannot map further targets."},
            {"id": "B", "text": "Ignore — internal scans are probably from IT", "is_correct": False,
             "explanation": "Incorrect. At 3 AM with no change window, this is suspicious. Legitimate IT scans are scheduled and documented, not performed from user workstations.",
             "consequences": "The attacker completes network mapping, identifies vulnerable services, and proceeds to exploit them for lateral movement."},
            {"id": "C", "text": "Block the host's access to the internet only", "is_correct": False,
             "explanation": "Incorrect. The scanning is internal (LAN-to-LAN). Blocking internet access doesn't stop internal reconnaissance.",
             "consequences": "Internal scanning continues unimpeded. The attacker maps all internal services and begins exploitation."},
            {"id": "D", "text": "Send an email to the machine's assigned user asking about the activity", "is_correct": False,
             "explanation": "Incorrect. The machine is likely compromised — the user may not be aware. This delays response by hours while the attack progresses.",
             "consequences": "The attacker has hours to complete reconnaissance, exploit services, and move laterally before anyone acts on the email reply."}
        ],
        "correct_response_id": "A",
        "mitigation_guidance": "1. Implement network segmentation with micro-segmentation\n2. Deploy internal IDS/IPS sensors\n3. Use host-based firewalls to limit outbound connections\n4. Monitor for unusual internal traffic patterns\n5. Maintain asset inventory to quickly identify rogue activity",
        "real_world_example": "During the 2013 Target breach, attackers used a compromised HVAC vendor machine to scan the internal network and locate POS systems."
    },
    {
        "scenario_id": "SC-006",
        "attack_type": "Masquerading",
        "mitre_id": "T1036",
        "mitre_name": "Masquerading",
        "tactic": "Defense Evasion",
        "kill_chain_stage": 7,
        "severity": "Medium",
        "description": "A process named 'svchost.exe' is running from an unusual directory (user's Desktop). The legitimate svchost.exe only runs from C:\\Windows\\System32. This indicates malware disguising itself as a Windows system process.",
        "realistic_logs": """[2026-05-09 10:33:12] edr: PROCESS_ANOMALY name=svchost.exe path=C:\\Users\\admin\\Desktop\\svchost.exe
[2026-05-09 10:33:12] edr: Expected path: C:\\Windows\\System32\\svchost.exe
[2026-05-09 10:33:13] edr: Digital signature: UNSIGNED (legitimate svchost.exe is Microsoft-signed)
[2026-05-09 10:33:13] edr: Parent process: explorer.exe (unusual — normally started by services.exe)
[2026-05-09 10:33:14] edr: Network activity: dst=45.33.32.156:8443 ENCRYPTED (unknown C2 server)
[2026-05-09 10:33:15] edr: File hash: a3f2b8... NOT in known-good database
[WARNING] Masquerading detected — fake svchost.exe running from user directory""",
        "options": [
            {"id": "A", "text": "Terminate the process, quarantine the file, and scan the endpoint", "is_correct": True,
             "explanation": "Correct! The process is clearly malicious (wrong path, unsigned, unknown hash). Terminating and quarantining removes the immediate threat while scanning catches any additional payloads.",
             "consequences": "The malware is stopped and preserved for analysis. C2 communication ceases. Full endpoint scan may reveal additional compromises."},
            {"id": "B", "text": "Allow it — svchost.exe is a normal Windows process", "is_correct": False,
             "explanation": "Incorrect. While svchost.exe is legitimate when running from System32, this instance is from the Desktop, unsigned, and connecting to an unknown server.",
             "consequences": "The malware continues operating with C2 access. Data exfiltration, keylogging, or ransomware deployment may follow."},
            {"id": "C", "text": "Rename the file so it can't run again", "is_correct": False,
             "explanation": "Incorrect. The currently running process remains active in memory. Renaming doesn't terminate it, and sophisticated malware can recreate itself.",
             "consequences": "The malware continues running in memory. It may detect the rename and create a new copy, or the persistence mechanism recreates it."},
            {"id": "D", "text": "Block port 8443 on the firewall", "is_correct": False,
             "explanation": "Partially correct but insufficient. Blocking the port stops this C2 channel, but the malware remains active and may use alternative ports or protocols.",
             "consequences": "C2 on port 8443 is blocked but the malware switches to HTTPS on port 443 (which you can't easily block). The root cause remains."}
        ],
        "correct_response_id": "A",
        "mitigation_guidance": "1. Use application whitelisting (AppLocker/WDAC)\n2. Monitor process execution paths vs expected locations\n3. Enforce code signing policies\n4. Deploy EDR with behavioral analysis\n5. Regularly audit running processes against known-good baselines",
        "real_world_example": "APT29 (Cozy Bear) frequently masquerades malware as legitimate Windows processes to evade detection during espionage campaigns."
    },
]


def get_all_scenarios():
    """Return all training scenarios."""
    return SCENARIOS


def get_scenario_by_mitre_id(mitre_id):
    """Find scenario matching a MITRE technique ID."""
    for s in SCENARIOS:
        if s["mitre_id"] == mitre_id:
            return s
    return None


def get_scenario_by_attack_type(attack_type):
    """Find scenario matching an attack type name (case-insensitive partial match)."""
    attack_lower = attack_type.lower()
    for s in SCENARIOS:
        if attack_lower in s["attack_type"].lower():
            return s
    return None


def get_random_scenario():
    """Return a random training scenario."""
    return random.choice(SCENARIOS)


def generate_scenario_from_detection(detection):
    """Match a live detection to a training scenario.

    Tries mitre_id first, then attack_type, then falls back to random.
    """
    mitre_id = detection.get("mitre_id", "")
    scenario = get_scenario_by_mitre_id(mitre_id)
    if scenario:
        return scenario

    attack_type = detection.get("attack_type", "")
    scenario = get_scenario_by_attack_type(attack_type)
    if scenario:
        return scenario

    return get_random_scenario()
