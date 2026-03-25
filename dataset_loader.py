"""
dataset_loader.py — Load and manage attack patterns from JSON datasets.

This module reads JSON datasets generated from OWASP CRS rules and
compiles them into an in-memory dictionary.
"""

import os
import json
import logging
from pathlib import Path

# Directories
PROJECT_ROOT = Path(__file__).resolve().parent
DATASETS_DIR = PROJECT_ROOT / 'datasets'

def load_datasets():
    """
    Load all JSON datasets from the datasets directory of the honeypot.
    
    Returns:
        dict: Geographic mapping of attack types to combined lists of raw regex strings.
              {"SQL Injection": {"severity": "High", "patterns": ["pattern1", "pattern2", ...]}, "XSS": {...}}
    """
    attack_data = {}
    
    if not DATASETS_DIR.exists():
        logging.warning("Datasets directory not found. Please run dataset_generator.py first.")
        # Fallback to local directory datasets if present (for flexibility)
        local_datasets = PROJECT_ROOT / 'datasets'
        if local_datasets.exists():
            DATASETS_DIR_USED = local_datasets
        else:
            return attack_data
    else:
        DATASETS_DIR_USED = DATASETS_DIR

    for file_path in DATASETS_DIR_USED.glob('*.json'):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            attack_type = data.get('attack_type')
            patterns = data.get('patterns', [])
            severity = data.get('severity', 'Medium')
            
            if attack_type and patterns:
                if attack_type not in attack_data:
                    attack_data[attack_type] = {"severity": severity, "patterns": []}
                attack_data[attack_type]["patterns"].extend(patterns)
                # Keep the highest severity if merging multiple files
                if severity == 'Critical':
                    attack_data[attack_type]["severity"] = 'Critical'
                
        except Exception as e:
            logging.error(f"Error loading dataset {file_path.name}: {e}")
            
    return attack_data

def get_compiled_patterns():
    """
    Loads raw patterns and returns a dictionary of compiled regex patterns
    grouped by attack type.
    """
    import re
    
    raw_data = load_datasets()
    compiled_data = {}
    
    for attack_type, info in raw_data.items():
        compiled_list = []
        for p in info["patterns"]:
            try:
                compiled_list.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                pass
                
        compiled_data[attack_type] = {
            "severity": info["severity"],
            "patterns": compiled_list
        }
        logging.info(f"Loaded {len(compiled_list)} compiled patterns for {attack_type}")
        
    return compiled_data

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    patterns = get_compiled_patterns()
    for atype, p_list in patterns.items():
        print(f"{atype}: {len(p_list)} patterns")
