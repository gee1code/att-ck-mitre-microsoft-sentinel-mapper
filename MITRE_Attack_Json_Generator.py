import os
import json
import pandas as pd
import re
import requests
from collections import Counter

# 📂 Define Directories
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_FOLDER = os.path.join(SCRIPT_DIR, "Sentinel_JSON")  # Place all JSONs here
OUTPUT_EXCEL = os.path.join(SCRIPT_DIR, "Consolidated_Analytical_Rules.xlsx")
FINAL_JSON = os.path.join(SCRIPT_DIR, "attack_layer.json")

# ✅ MITRE ATT&CK Mappings
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# 🔎 List of known Microsoft Sentinel tables
TABLES = [
    "AzureActivity", "F5Telemetry_LTM_CL", "F5Telemetry_system_CL", "OfficeActivity", 
    "SecurityAlert", "SecurityIncident", "DeviceImageLoadEvents", "DeviceInfo", 
    "DeviceLogonEvents", "DeviceNetworkEvents", "DeviceNetworkInfo", "DeviceRegistryEvents", 
    "DeviceFileCertificateInfo", "SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs", 
    "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs", "AADProvisioningLogs",
    "imAuthentication", "CommonSecurityLog", "DeviceEvents", "UrlClickEvents", 
    "CiscoSecureEndpoint", "ThreatIntelligenceIndicator", "IdentityLogonEvents", "Heartbeat", 
    "DeviceProcessEvents", "SecurityEvent", "Syslog", "DeviceFileEvents", "AzureDiagnostics", 
    "EmailEvents", "F5Telemetry_ASM_CL", "W3CIISLog", "Event", "_Im_NetworkSession", 
    "imProcessCreate", "_Im_Dns", "Dynamics365Activity", "_Im_WebSession", "ADFSSignInLogs", 
    "AlertInfo", "AzureDevOpsAuditing"
]

# ✅ Tactic Mapping
TACTIC_MAPPING = {
    "persistence": "persistence",
    "commandandcontrol": "command-and-control",
    "initialaccess": "initial-access",
    "defenseevasion": "defense-evasion",
    "execution": "execution",
    "credentialaccess": "credential-access",
    "discovery": "discovery",
    "lateralmovement": "lateral-movement",
    "privilegeescalation": "privilege-escalation",
    "impact": "impact",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "resourcedevelopment": "resource-development",
    "reconnaissance": "reconnaissance",
}

# 🚀 Step 1: Fetch MITRE ATT&CK technique-to-tactic mappings
def fetch_mitre_mappings():
    print("🔄 Fetching MITRE ATT&CK framework data...")
    try:
        response = requests.get(MITRE_URL)
        response.raise_for_status()
        attack_data = response.json()
        
        technique_tactic_mapping = {}
        for obj in attack_data["objects"]:
            if obj.get("type") == "attack-pattern":
                technique_id = next((ext["external_id"] for ext in obj.get("external_references", []) if ext["source_name"] == "mitre-attack"), None)
                tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", []) if phase["kill_chain_name"] == "mitre-attack"]
                if technique_id:
                    technique_tactic_mapping[technique_id] = set(tactics)

        print("✅ MITRE ATT&CK data successfully retrieved.")
        return technique_tactic_mapping
    except Exception as e:
        print(f"❌ Error fetching MITRE ATT&CK data: {e}")
        return {}

# 🚀 Step 2: Process JSON Files → Excel
def process_json_to_excel():
    print("🔄 Processing JSON files from Microsoft Sentinel...")

    json_files = [os.path.join(JSON_FOLDER, f) for f in os.listdir(JSON_FOLDER) if f.endswith(".json")]
    
    if not json_files:
        print("⚠️ No JSON files found in the 'Sentinel_JSON' folder. Exiting.")
        return None
    
    all_data = []
    
    for json_file_path in json_files:
        print(f"📂 Processing: {json_file_path}")
        try:
            with open(json_file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
        except Exception as e:
            print(f"❌ Error reading {json_file_path}: {e}")
            continue

        for item in data.get('resources', []):
            properties = item.get('properties', {})
            query = properties.get('query', '')

            properties['table_name'] = ', '.join([t for t in TABLES if t in query]) or None
            properties['watchlist'] = ', '.join(re.findall(r'_GetWatchlist\(["\']([^"\']+)["\']\)', query)) or None
            properties['Client'] = os.path.basename(os.path.dirname(json_file_path)).split("_")[-1]
            properties['Source_File'] = os.path.basename(json_file_path)

            all_data.append(properties)

    if not all_data:
        print("⚠️ No valid data extracted. Exiting.")
        return None

    df = pd.DataFrame(all_data)
    df.to_excel(OUTPUT_EXCEL, index=False)
    print(f"✅ Success! Extracted data saved to '{OUTPUT_EXCEL}'")
    return OUTPUT_EXCEL

# 🚀 Step 3: Convert Excel → ATT&CK JSON with Color Logic
def convert_excel_to_attack_json(excel_file, mitre_mappings):
    print("🔄 Converting Excel data to ATT&CK Navigator JSON...")

    df = pd.read_excel(excel_file)
    techniques = []
    
    technique_counter = Counter()

    for _, row in df.iterrows():
        raw_tactics = row.get("tactics", "").strip("[]").replace("'", "").split(", ")
        raw_techniques = row.get("techniques", "").strip("[]").replace("'", "").split(", ")

        for tech in raw_techniques:
            tech = tech.strip()
            if tech in mitre_mappings:
                for valid_tactic in mitre_mappings[tech]:
                    formatted_tactic = TACTIC_MAPPING.get(valid_tactic.replace(" ", "").lower(), valid_tactic)
                    technique_counter[tech] += 1
                    techniques.append({
                        "techniqueID": tech,
                        "tactic": formatted_tactic,
                        "color": "#fca2a2",  # Placeholder color before final logic
                        "comment": "",
                        "enabled": True,
                        "metadata": [],
                        "links": [],
                        "showSubtechniques": False
                    })

    # Now assign the correct colors based on the count of tactics
    for technique in techniques:
        tech_id = technique["techniqueID"]
        tactic_count = technique_counter[tech_id]
        
        # Apply color based on count
        if tactic_count < 5:
            technique["color"] = "#e4ecff"
        elif 5 <= tactic_count < 10:
            technique["color"] = "#617fe6"
        else:
            technique["color"] = "#5056b5"

    # Predefined sections
    attack_json = {
        "name": "layer",
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "",
        "filters": {
            "platforms": [
                "Windows", "Linux", "macOS", "Network", "PRE", "Containers", "IaaS", "SaaS",
                "Office Suite", "Identity Provider"
            ]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "none"
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False
    }

    with open(FINAL_JSON, 'w') as f:
        json.dump(attack_json, f, indent=4)

    print(f"✅ Final ATT&CK JSON saved to '{FINAL_JSON}'")

# 🚀 Main Execution
def main():
    mitre_mappings = fetch_mitre_mappings()
    if not mitre_mappings:
        return
    
    excel_file = process_json_to_excel()
    if excel_file:
        convert_excel_to_attack_json(excel_file, mitre_mappings)

if __name__ == "__main__":
    main()
