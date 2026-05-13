"""
UNSW-NB15 attack category → MITRE ATT&CK technique mapping.

The UNSW-NB15 dataset uses 9 attack categories + Normal.
Each is mapped to the most relevant MITRE ATT&CK technique.
"""

# UNSW-NB15 attack label → MITRE technique ID
NETWORK_ATTACK_TO_MITRE = {
    "Normal": None,            # Benign traffic
    "Fuzzers": "T1190",        # Exploit Public-Facing Application
    "Analysis": "T1046",       # Network Service Scanning
    "Backdoors": "T1059",      # Command and Scripting Interpreter
    "DoS": "T1499",            # Endpoint Denial of Service
    "Exploits": "T1210",       # Exploitation of Remote Services
    "Generic": "T1071",        # Application Layer Protocol
    "Reconnaissance": "T1595", # Active Scanning
    "Shellcode": "T1059",      # Command and Scripting Interpreter
    "Worms": "T1570",          # Lateral Tool Transfer
}

# Severity rating for each attack category
ATTACK_SEVERITY = {
    "Normal": "None",
    "Fuzzers": "Medium",
    "Analysis": "Low",
    "Backdoors": "High",
    "DoS": "High",
    "Exploits": "High",
    "Generic": "Medium",
    "Reconnaissance": "Low",
    "Shellcode": "High",
    "Worms": "High",
}

# Kill chain tactic for each MITRE technique
TECHNIQUE_TO_TACTIC = {
    "T1190": "Initial Access",
    "T1046": "Discovery",
    "T1059": "Execution",
    "T1499": "Impact",
    "T1210": "Lateral Movement",
    "T1071": "Command and Control",
    "T1595": "Reconnaissance",
    "T1570": "Lateral Movement",
    # Include document scanner techniques too
    "T1566": "Initial Access",
    "T1036": "Defense Evasion",
    "T1003": "Credential Access",
    "T1110": "Credential Access",
    "T1056": "Collection",
    "T1078": "Persistence",
}
