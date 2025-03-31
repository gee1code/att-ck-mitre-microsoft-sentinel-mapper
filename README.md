
# MITRE ATT&CK Navigator JSON Generator for Microsoft Sentinel Rules

This project is designed to process Microsoft Sentinel rule JSON files (from Analytics Rules) stored in the `Sentinel_JSON` folder, map them to the MITRE ATT&CK framework, and generate a formatted output suitable for use in ATT&CK Navigator. The color of techniques is dynamically adjusted based on how frequently they are used across different tactics.

---

## Prerequisites

Before you begin, make sure you have the following installed:

- **Python 3.x**: Python 3.6 or higher is required.
- **Pip**: Python’s package installer.
  
### Required Python Libraries

This project uses the following Python libraries:

- `requests`
- `pandas`
- `openpyxl` (for working with Excel files)
- `re`
- `collections`

You can install the required dependencies by running:

```bash
pip install -r requirements.txt
```

If you don’t have `requirements.txt`, you can install each dependency individually using pip:

```bash
pip install requests pandas openpyxl
```

---

## Project Structure

```plaintext
├── MITRE_Attack_Json_Generator.py  # The script to fetch MITRE data and process Sentinel JSON to ATT&CK JSON
├── requirements.txt               # List of required dependencies
├── Sentinel_JSON/                 # Folder to store Microsoft Sentinel JSON files (rules)
├── Consolidated_Analytical_Rules.xlsx  # Excel output generated from Sentinel JSON files
├── attack_layer.json              # Final output MITRE ATT&CK Navigator JSON file
```

---

## How to Use

### Step 1: Download Sentinel JSON Files

Download the Microsoft Sentinel JSON rule files. You may need to download multiple JSON files, as there is no option to select all rules at once in Microsoft Sentinel. Place these files directly into the `Sentinel_JSON/` folder in your project directory.

### Step 2: Run the `MITRE_Attack_Json_Generator.py` Script

1. **Open a terminal or command prompt**.
2. **Navigate to the project directory** where the script is located.
3. **Run the script** by executing the following command:

```bash
python MITRE_Attack_Json_Generator.py
```

The script will automatically process all JSON files located in the `Sentinel_JSON/` folder.

### Step 3: Review the Processed Excel Output

Once the Sentinel JSON files are processed, an Excel file (`Consolidated_Analytical_Rules.xlsx`) will be generated. It contains details of each rule, including associated tactics and techniques. This file is used as an intermediary step before generating the final ATT&CK Navigator JSON.

---

### Step 4: MITRE ATT&CK Navigator JSON Output

After processing the Sentinel JSON files into Excel format, the script will convert it into a properly formatted **MITRE ATT&CK Navigator JSON** file. The final output will be saved as `attack_layer.json`.

The color of techniques in this JSON file is automatically assigned based on the number of tactics associated with them:

- **Less than 5 tactics**: Color `#e4ecff`
- **5 to 9 tactics**: Color `#617fe6`
- **10 or more tactics**: Color `#5056b5`

This generated file can be uploaded to the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for analysis.

---

## Configuration

You can customize the following parts of the script:

- **Sentinel JSON Folder**: The folder where you store the downloaded Sentinel JSON files is specified in the script (`Sentinel_JSON/`). Make sure the files are in this folder.
- **MITRE Mappings URL**: The script fetches the latest MITRE ATT&CK framework from the official [MITRE ATT&CK repository](https://github.com/mitre/cti). This URL is hardcoded in the script.
  
---

## Example Output

### Final ATT&CK Navigator JSON (`attack_layer.json`)

The final output will be a JSON structure like this:

```json
{
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
      "Windows", "Linux", "macOS", "Network", "PRE", "Containers", "IaaS", "SaaS", "Office Suite", "Identity Provider"
    ]
  },
  "sorting": 0,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": false,
    "showName": true,
    "showAggregateScores": false,
    "countUnscored": false,
    "expandedSubtechniques": "none"
  },
  "hideDisabled": false,
  "techniques": [
    {
      "techniqueID": "T1078",
      "tactic": "persistence",
      "color": "#e4ecff",
      "comment": "",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1547",
      "tactic": "privilege-escalation",
      "color": "#5056b5",
      "comment": "",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    }
  ],
  "gradient": {
    "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
    "minValue": 0,
    "maxValue": 100
  },
  "legendItems": [],
  "metadata": [],
  "links": [],
  "showTacticRowBackground": false,
  "tacticRowBackground": "#dddddd",
  "selectTechniquesAcrossTactics": true,
  "selectSubtechniquesWithParent": false,
  "selectVisibleTechniques": false
}
```

### Generated Excel File (`Consolidated_Analytical_Rules.xlsx`)

The generated Excel file will contain details such as:

- Technique ID
- Associated Tactics
- Query (to help link techniques to specific Sentinel rules)
- Watchlists used
- Client/Source information

---

## Troubleshooting

- **Error: JSON Decoding Failure**: If you see errors about decoding JSON files, ensure that the downloaded Sentinel JSON files are correctly formatted.
- **Error: Missing JSON Key**: If the script cannot find the key `resources` in the JSON files, it may indicate a malformed file.
  
---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### Feel free to contribute or raise issues if you encounter any problems!
