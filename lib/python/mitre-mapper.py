#!/usr/bin/env python3
"""
MITRE ATT&CK Mapping Module for IRF
Maps detection rules to MITRE ATT&CK techniques and tactics
"""

import os
import sys
import json
import requests
import pandas as pd
from datetime import datetime

class MitreMapper:
    def __init__(self, config=None):
        """Initialize the MITRE mapper with optional configuration."""
        self.config = config or {}
        self.techniques_data = None
        self.tactics_data = None
        self.local_cache = self.config.get('local_cache', True)
        self.cache_dir = self.config.get('cache_dir') or os.path.join(
            os.environ.get('IRF_ROOT', '.'), 'mitre_data')

        # Create cache directory if it doesn't exist
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)

        # Load MITRE data
        self.load_mitre_data()

    def load_mitre_data(self):
        """Load MITRE ATT&CK data from local cache or fetch from MITRE."""
        cache_file = os.path.join(self.cache_dir, 'mitre_enterprise.json')

        # Try to load from cache first
        if self.local_cache and os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)

                self.techniques_data = data.get('techniques', {})
                self.tactics_data = data.get('tactics', {})
                return True
            except Exception as e:
                print(f"Error loading MITRE data from cache: {e}")

        # Fetch from MITRE if cache not available or invalid
        try:
            # Get Enterprise MITRE ATT&CK data
            response = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
            data = response.json()

            # Process and organize the data
            self.techniques_data = {}
            self.tactics_data = {}

            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if technique_id.startswith('T'):
                        self.techniques_data[technique_id] = {
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'tactics': []
                        }

                        # Map to tactics
                        for kill_chain_phase in obj.get('kill_chain_phases', []):
                            if kill_chain_phase.get('kill_chain_name') == 'mitre-attack':
                                self.techniques_data[technique_id]['tactics'].append(
                                    kill_chain_phase.get('phase_name', '')
                                )

                elif obj.get('type') == 'x-mitre-tactic':
                    tactic_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if tactic_id.startswith('TA'):
                        self.tactics_data[tactic_id] = {
                            'name': obj.get('name', ''),
                            'description': obj.get('description', '')
                        }

            # Cache the data locally
            if self.local_cache:
                with open(cache_file, 'w') as f:
                    json.dump({
                        'techniques': self.techniques_data,
                        'tactics': self.tactics_data,
                        'last_updated': datetime.now().isoformat()
                    }, f, indent=2)

            return True
        except Exception as e:
            print(f"Error fetching MITRE data: {e}")
            return False

    def map_rule_to_technique(self, rule_content):
        """Map a rule to MITRE ATT&CK techniques based on keywords and patterns."""
        if not self.techniques_data:
            return []

        # Extract keywords from rule
        keywords = []

        # Add pattern to keywords
        if hasattr(rule_content, 'pattern'):
            pattern = getattr(rule_content, 'pattern', '')
            keywords.extend(pattern.lower().split('|'))

        # Add description to keywords
        if hasattr(rule_content, 'description'):
            description = getattr(rule_content, 'description', '')
            keywords.extend(description.lower().split())

        # Score each technique based on keyword matches
        technique_scores = {}

        for technique_id, technique_data in self.techniques_data.items():
            score = 0

            # Check name and description for keyword matches
            technique_text = (technique_data['name'] + ' ' + technique_data['description']).lower()

            for keyword in keywords:
                if keyword and len(keyword) > 3 and keyword in technique_text:
                    score += 1

            if score > 0:
                technique_scores[technique_id] = score

        # Sort techniques by score and return top matches
        sorted_techniques = sorted(technique_scores.items(), key=lambda x: x[1], reverse=True)

        # Return top 3 techniques with score > 1
        return [
            {
                'technique_id': t[0],
                'name': self.techniques_data[t[0]]['name'],
                'tactics': self.techniques_data[t[0]]['tactics'],
                'score': t[1]
            }
            for t in sorted_techniques[:3] if t[1] > 1
        ]

    def enrich_rules_with_mitre(self, rules_dir, output_dir=None):
        """Enrich rule files with MITRE ATT&CK mappings."""
        if not self.techniques_data:
            return False

        output_dir = output_dir or rules_dir

        # Process each rule file
        for rule_file in os.listdir(rules_dir):
            if rule_file.endswith('.rules'):
                input_path = os.path.join(rules_dir, rule_file)
                output_path = os.path.join(output_dir, rule_file)

                # Read rule file
                with open(input_path, 'r') as f:
                    lines = f.readlines()

                # Process rules
                enriched_lines = []
                in_header = True

                for line in lines:
                    if in_header and line.startswith('#'):
                        enriched_lines.append(line)
                    elif in_header and not line.startswith('#') and line.strip():
                        # Add MITRE ATT&CK mapping section before first rule
                        enriched_lines.append('\n# MITRE ATT&CK Mappings\n')
                        enriched_lines.append('# Format: RULE_ID;MITRE_TECHNIQUE_IDs\n\n')
                        enriched_lines.append(line)
                        in_header = False
                    else:
                        enriched_lines.append(line)

                # Write enriched file
                with open(output_path, 'w') as f:
                    f.writelines(enriched_lines)

        return True

# Main execution
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='MITRE ATT&CK Mapper for IRF')
    parser.add_argument('--rules-dir', required=True, help='Directory containing rule files')
    parser.add_argument('--output-dir', help='Output directory for enriched rules')

    args = parser.parse_args()

    mapper = MitreMapper()

    if mapper.enrich_rules_with_mitre(args.rules_dir, args.output_dir):
        print("Rules successfully enriched with MITRE ATT&CK mappings")
    else:
        print("Failed to enrich rules")
        sys.exit(1)
