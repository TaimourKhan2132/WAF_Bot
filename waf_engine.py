import re
from knowledge_base import waf_rules, concepts #importing from my second python file i.e the dictionary

def analyze_input(user_input):
    results = []
    user_input_lower = user_input.lower()

    # QUERY TYPE 2: CONCEPT LOOKUP 
    # Check if user is asking "What is X?"
    for key, definition in concepts.items():
        if key in user_input_lower and ("what is" in user_input_lower or "define" in user_input_lower):
            return [{
                "rule_id": "INFO",
                "attack_type": "Concept Definition",
                "risk_level": "Informational",
                "description": definition,
                "match_found": key
            }]

    # QUERY TYPE 3: RULE ID LOOKUP 
    # Check if user is asking for a specific rule ID (e.g. "Rule 1001")
    id_match = re.search(r"rule\s+(\d{4})", user_input_lower)
    if id_match:
        rule_id = int(id_match.group(1))
        for rule in waf_rules:
            if rule["id"] == rule_id:
                return [{
                    "rule_id": rule["id"],
                    "attack_type": rule["name"],
                    "risk_level": "Informational",
                    "description": rule["description"],
                    "match_found": f"Lookup for ID {rule_id}"
                }]

    # QUERY TYPE 1: THREAT ANALYSIS
    if not user_input or not isinstance(user_input, str):
        return []
    
    for rule in waf_rules:
        try:
            match = re.search(rule["pattern"], user_input, re.IGNORECASE)
            if match:
                results.append({
                    "rule_id": rule["id"],
                    "attack_type": rule["name"],
                    "risk_level": rule["risk"],
                    "description": rule["description"],
                    "match_found": match.group(0)
                })
        except re.error:
            continue
            
    return results