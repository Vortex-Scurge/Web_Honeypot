#!/usr/bin/env python3
"""
dataset_stats.py — Analyze and display statistics for the generated JSON attack datasets.
"""

import os
import json
from pathlib import Path

DATASETS_DIR = Path('/home/noxir/antigravity/web-honeypot/datasets')

def main():
    if not DATASETS_DIR.exists():
        print("Datasets directory not found. Please run dataset_generator.py first.")
        return

    stats = {}
    total_patterns = 0
    total_files = 0
    
    for file_path in DATASETS_DIR.glob('*.json'):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            attack_type = data.get('attack_type', file_path.stem)
            patterns = data.get('patterns', [])
            stats[attack_type] = len(patterns)
            total_patterns += len(patterns)
            total_files += 1
        except Exception as e:
            print(f"Error reading {file_path.name}: {e}")

    # Sort stats by pattern count descending
    sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)

    print("=" * 50)
    print("📊 DATASET STATISTICS MODULE")
    print("=" * 50)
    print(f"Sources:          OWASP CRS + PayloadsAllTheThings")
    print(f"Attack Types:     {total_files}")
    print(f"Total Patterns:   {total_patterns}")
    print(f"Coverage Goal:    Comprehensive Multi-vector Detection")
    print("-" * 50)
    print(f"{'Attack Type':<30} | {'Patterns'}")
    print("-" * 50)
    
    for attack_type, count in sorted_stats:
        print(f"{attack_type:<30} | {count}")
    
    print("=" * 50)

if __name__ == '__main__':
    main()
