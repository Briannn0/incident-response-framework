#!/usr/bin/env python3
#
# Correlation engine for the Incident Response Framework
# Handles linking related events across different log sources

import os
import sys
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import traceback

# Add path for other IRF modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def handle_errors(func):
    """Decorator for standardized error handling"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_info = {
                "status": "error",
                "error_type": type(e).__name__,
                "error_message": str(e)
            }
            sys.stderr.write(json.dumps(error_info) + "\n")
            sys.exit(1)
    return wrapper

class EventCorrelator:
    def __init__(self, config=None):
        """Initialize the correlator with optional configuration."""
        self.config = config or {}
        self.events = []
        self.correlation_window = self.config.get('correlation_window', 300)  # 5 minutes default
        
    def load_events(self, events_file):
        """Load detected events from a file."""
        try:
            # Assuming events are stored in a normalized format
            df = pd.read_csv(events_file, sep='\t')
            self.events = df.to_dict('records')
            return True
        except Exception as e:
            print(f"Error loading events: {e}")
            return False
    
    def correlate_by_ip(self):
        """Correlate events based on IP addresses."""
        if not self.events:
            return []
            
        # Convert to pandas DataFrame for easier manipulation
        df = pd.DataFrame(self.events)
        
        # Group events by IP address - this creates separate groups for each unique IP
        if 'ip_address' in df.columns:
            ip_groups = df.groupby('ip_address')
            correlated = []
            
            for ip, group in ip_groups:
                if len(group) > 1:  # Check if there are 2 or more events from the same IP address
                    # Create a dictionary with information about this group of related events
                    correlated.append({
                        'correlation_type': 'ip_address',  # Label showing how these events are related
                        'value': ip,  # The actual IP address that connects these events
                        'event_count': len(group),  # How many events came from this IP
                        'events': group.to_dict('records'),  # All the event details stored as a list
                        'severity': self._calculate_severity(group)  # How serious this group of events is
                    })
            
            return correlated  # Return all the groups of related events we found
        return []  # Return empty list if we couldn't find the IP address column
    
    def correlate_by_time_window(self):
        """Find events that happened close together in time, which might be related."""
        if not self.events:
            return []  # If we have no events, return an empty list
            
        df = pd.DataFrame(self.events)
        
        # Check if timestamp column exists and convert text dates to datetime objects
        # This allows us to perform time calculations and comparisons
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df = df.sort_values('timestamp')  # Sort events from earliest to latest
            
            # Now we'll look for sequences of events that happened within our time window
            # (The time window is set when creating the correlator object)
            correlated = []  # This will hold our groups of related events
            current_sequence = []  # Temporary list to build each group
            
            for i, row in df.iterrows():
                if not current_sequence:
                    current_sequence.append(row.to_dict())  # Start a new sequence with this event
                else:
                    last_time = pd.to_datetime(current_sequence[-1]['timestamp'])
                    current_time = pd.to_datetime(row['timestamp'])
                    
                    if (current_time - last_time).total_seconds() <= self.correlation_window:
                        current_sequence.append(row.to_dict())  # Add event to current sequence
                    else:
                        if len(current_sequence) > 1:
                            correlated.append({
                                'correlation_type': 'time_window',
                                'window_seconds': self.correlation_window,
                                'event_count': len(current_sequence),
                                'events': current_sequence,
                                'start_time': current_sequence[0]['timestamp'],
                                'end_time': current_sequence[-1]['timestamp'],
                                'severity': self._calculate_severity(pd.DataFrame(current_sequence))
                            })
                        current_sequence = [row.to_dict()]  # Start a new sequence
            
            # Handle the last sequence
            if len(current_sequence) > 1:
                correlated.append({
                    'correlation_type': 'time_window',
                    'window_seconds': self.correlation_window,
                    'event_count': len(current_sequence),
                    'events': current_sequence,
                    'start_time': current_sequence[0]['timestamp'],
                    'end_time': current_sequence[-1]['timestamp'],
                    'severity': self._calculate_severity(pd.DataFrame(current_sequence))
                })
                
            return correlated
        return []
    
    def correlate_by_attack_chain(self):
        """Identify potential attack chains based on event types and sequence."""
        if not self.events:
            return []
            
        df = pd.DataFrame(self.events)
        
        # Define known attack chain patterns
        attack_patterns = [
            {
                'name': 'Brute Force to Privilege Escalation',
                'steps': ['BF-', 'PE-'],
                'max_time_gap': 3600  # 1 hour between steps
            },
            {
                'name': 'Unauthorized Access to Malware Execution',
                'steps': ['UA-', 'MW-'],
                'max_time_gap': 1800  # 30 minutes between steps
            }
        ]
        
        correlated_chains = []
        
        for pattern in attack_patterns:
            # Try to identify this pattern in the events
            chain = self._find_attack_chain(df, pattern)
            if chain:
                correlated_chains.append(chain)
                
        return correlated_chains
    
    def _find_attack_chain(self, df, pattern):
        """Helper method to identify a specific attack chain pattern."""
        if 'RULE_ID' not in df.columns or 'timestamp' not in df.columns:
            return None
            
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.sort_values('timestamp')
        
        # Look for events matching each step in the pattern
        matches = []
        for step in pattern['steps']:
            step_matches = df[df['RULE_ID'].str.startswith(step, na=False)]
            if len(step_matches) > 0:
                matches.append(step_matches.iloc[0].to_dict())
        
        # If we found all steps in the pattern
        if len(matches) == len(pattern['steps']):
            # Check if they occurred within the specified time gap
            times = [pd.to_datetime(m['timestamp']) for m in matches]
            valid_chain = True
            
            for i in range(1, len(times)):
                if (times[i] - times[i-1]).total_seconds() > pattern['max_time_gap']:
                    valid_chain = False
                    break
            
            if valid_chain:
                return {
                    'correlation_type': 'attack_chain',
                    'pattern_name': pattern['name'],
                    'events': matches,
                    'start_time': str(times[0]),
                    'end_time': str(times[-1]),
                    'duration_seconds': (times[-1] - times[0]).total_seconds(),
                    'severity': 'HIGH'
                }
        
        return None
    
    def _calculate_severity(self, events_df):
        """Calculate overall severity for a group of events."""
        severity_levels = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        
        if 'SEVERITY' in events_df.columns:
            severities = events_df['SEVERITY'].apply(lambda x: severity_levels.get(x, 0))
            max_severity = severities.max()
            
            # Map back to string representation
            for name, level in severity_levels.items():
                if level == max_severity:
                    return name
        
        return 'MEDIUM'  # Default
    
    def save_correlations(self, correlations, output_file):
        """Save correlation results to a file."""
        try:
            with open(output_file, 'w') as f:
                json.dump(correlations, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving correlations: {e}")
            return False
            
    def run_all_correlations(self, output_file=None):
        """Run all correlation methods and combine results."""
        correlations = []
        
        # Run each correlation method
        ip_correlations = self.correlate_by_ip()
        time_correlations = self.correlate_by_time_window()
        chain_correlations = self.correlate_by_attack_chain()
        
        correlations.extend(ip_correlations)
        correlations.extend(time_correlations)
        correlations.extend(chain_correlations)
        
        # Save to file if specified
        if output_file and correlations:
            self.save_correlations(correlations, output_file)
            
        return correlations


# Command-line interface
if __name__ == "__main__":
    import argparse
    
    @handle_errors
    def main():
        parser = argparse.ArgumentParser(description='IRF Event Correlator')
        parser.add_argument('--events', required=True, help='Path to events file')
        parser.add_argument('--output', required=True, help='Path to output file')
        parser.add_argument('--window', type=int, default=300, help='Correlation time window in seconds')
        args = parser.parse_args()
        
        correlator = EventCorrelator({'correlation_window': args.window})
        
        if correlator.load_events(args.events):
            correlations = correlator.run_all_correlations(args.output)
            print(f"Found {len(correlations)} correlation groups")
            print(f"Results saved to {args.output}")
        else:
            print("Failed to load events.")
            sys.exit(1)
    
    main()