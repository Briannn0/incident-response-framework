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

class PatternEngine:
    """Flexible pattern matching engine for attack sequences."""
    
    def __init__(self):
        self.patterns = {}
        
    def add_pattern(self, pattern_id, pattern_def):
        """Add a pattern definition to the engine.
        
        Args:
            pattern_id: Unique identifier for the pattern
            pattern_def: Dictionary containing pattern definition
                {
                    'name': 'Pattern name',
                    'sequence': [
                        {'rule_pattern': 'BF-.*', 'min_count': 3, 'max_time': 300},
                        {'rule_pattern': 'PE-.*', 'min_count': 1, 'max_time': 1800}
                    ],
                    'conditions': [
                        'same_ip_address',
                        'same_username'
                    ],
                    'max_gap': 3600,
                    'severity': 'HIGH'
                }
        """
        self.patterns[pattern_id] = pattern_def
        
    def load_patterns_from_file(self, pattern_file):
        """Load pattern definitions from a JSON file."""
        try:
            with open(pattern_file, 'r') as f:
                patterns = json.load(f)
                for pattern_id, pattern_def in patterns.items():
                    self.add_pattern(pattern_id, pattern_def)
            return True
        except Exception as e:
            print(f"Error loading patterns: {e}")
            return False
            
    def match_sequences(self, events_df):
        """Find sequences matching defined patterns in event data.
        
        Args:
            events_df: DataFrame containing event data
            
        Returns:
            List of dictionaries with matched patterns
        """
        matches = []
        
        for pattern_id, pattern in self.patterns.items():
            # Find events matching each step in the sequence
            sequence_matches = self._match_sequence_steps(events_df, pattern)
            
            if sequence_matches:
                for match in sequence_matches:
                    matches.append({
                        'pattern_id': pattern_id,
                        'pattern_name': pattern['name'],
                        'events': match['events'],
                        'start_time': match['start_time'],
                        'end_time': match['end_time'],
                        'duration_seconds': match['duration_seconds'],
                        'confidence': match['confidence'],
                        'severity': pattern.get('severity', 'MEDIUM')
                    })
                    
        return matches
        
    def _match_sequence_steps(self, events_df, pattern):
        """Match the sequence steps defined in a pattern."""
        if 'timestamp' not in events_df.columns or 'RULE_ID' not in events_df.columns:
            return []
            
        # Sort events by timestamp
        events_df = events_df.sort_values('timestamp')
        events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
        
        # Find events matching each step
        sequence_steps = pattern.get('sequence', [])
        step_matches = []
        
        for step in sequence_steps:
            rule_pattern = step.get('rule_pattern', '.*')
            min_count = step.get('min_count', 1)
            
            # Find events matching this step's rule pattern
            matching_events = events_df[events_df['RULE_ID'].str.match(rule_pattern)]
            
            if len(matching_events) >= min_count:
                step_matches.append({
                    'rule_pattern': rule_pattern,
                    'events': matching_events.to_dict('records')
                })
            else:
                # Not enough matches for this step
                return []
                
        # Check if we found matches for all steps
        if len(step_matches) != len(sequence_steps):
            return []
            
        # Check conditions like same_ip_address, same_username
        conditions = pattern.get('conditions', [])
        
        # Find valid sequences that satisfy all conditions
        sequences = self._find_valid_sequences(step_matches, conditions, pattern.get('max_gap', 3600))
        
        return sequences
        
    def _find_valid_sequences(self, step_matches, conditions, max_gap):
        """Find valid sequences that satisfy all conditions."""
        # Start with the first step events
        sequences = []
        
        for first_event in step_matches[0]['events']:
            # Try to build a sequence starting with this event
            sequence = [first_event]
            
            # Track if we can complete the sequence
            valid_sequence = self._extend_sequence(sequence, step_matches[1:], conditions, max_gap)
            
            if valid_sequence:
                # Calculate sequence metrics
                start_time = pd.to_datetime(sequence[0]['timestamp'])
                end_time = pd.to_datetime(sequence[-1]['timestamp'])
                duration = (end_time - start_time).total_seconds()
                
                # Add to valid sequences
                sequences.append({
                    'events': sequence,
                    'start_time': str(start_time),
                    'end_time': str(end_time),
                    'duration_seconds': duration,
                    'confidence': 1.0  # Perfect match
                })
                
        return sequences
        
    def _extend_sequence(self, current_sequence, remaining_steps, conditions, max_gap):
        """Recursively extend a sequence with remaining steps."""
        if not remaining_steps:
            return True
            
        # Get the last event in the current sequence
        last_event = current_sequence[-1]
        last_time = pd.to_datetime(last_event['timestamp'])
        
        # Try to find a matching event from the next step
        for next_event in remaining_steps[0]['events']:
            next_time = pd.to_datetime(next_event['timestamp'])
            
            # Check time gap constraint
            if (next_time - last_time).total_seconds() > max_gap:
                continue
                
            # Check all conditions
            if self._check_conditions(current_sequence, next_event, conditions):
                # Add this event to the sequence
                extended_sequence = current_sequence + [next_event]
                
                # Try to extend with the rest of the steps
                if self._extend_sequence(extended_sequence, remaining_steps[1:], conditions, max_gap):
                    # Update the current_sequence in place
                    current_sequence[:] = extended_sequence
                    return True
                    
        return False
        
    def _check_conditions(self, current_sequence, candidate_event, conditions):
        """Check if a candidate event satisfies all conditions with the current sequence."""
        for condition in conditions:
            if condition == 'same_ip_address':
                if 'ip_address' not in candidate_event:
                    return False
                    
                for event in current_sequence:
                    if 'ip_address' not in event or event['ip_address'] != candidate_event['ip_address']:
                        return False
                        
            elif condition == 'same_username':
                if 'username' not in candidate_event:
                    return False
                    
                for event in current_sequence:
                    if 'username' not in event or event['username'] != candidate_event['username']:
                        return False
                        
            # Add more conditions as needed
                
        return True

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
        self.pattern_engine = PatternEngine()
        
        # Load patterns from config if provided
        pattern_file = self.config.get('pattern_file')
        if pattern_file:
            self.pattern_engine.load_patterns_from_file(pattern_file)
        else:
            # Add default patterns
            self.pattern_engine.add_pattern('brute_force_to_privilege', {
                'name': 'Brute Force to Privilege Escalation',
                'sequence': [
                    {'rule_pattern': 'BF-.*', 'min_count': 3, 'max_time': 300},
                    {'rule_pattern': 'PE-.*', 'min_count': 1, 'max_time': 1800}
                ],
                'conditions': ['same_ip_address'],
                'max_gap': 3600,
                'severity': 'HIGH'
            })
            
            self.pattern_engine.add_pattern('unauthorized_to_malware', {
                'name': 'Unauthorized Access to Malware Execution',
                'sequence': [
                    {'rule_pattern': 'UA-.*', 'min_count': 1},
                    {'rule_pattern': 'MW-.*', 'min_count': 1}
                ],
                'conditions': ['same_ip_address'],
                'max_gap': 1800,
                'severity': 'HIGH'
            })
        
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
        """Identify potential attack chains using the flexible pattern engine."""
        if not self.events:
            return []
            
        # Convert to pandas DataFrame
        df = pd.DataFrame(self.events)
        
        # Use the pattern engine to find matches
        matches = self.pattern_engine.match_sequences(df)
        
        # Format results for compatibility with other correlation methods
        correlated_chains = []
        
        for match in matches:
            correlated_chains.append({
                'correlation_type': 'attack_chain',
                'pattern_name': match['pattern_name'],
                'events': match['events'],
                'start_time': match['start_time'],
                'end_time': match['end_time'],
                'duration_seconds': match['duration_seconds'],
                'severity': match['severity']
            })
            
        return correlated_chains
    
    def correlate_multi_stage_attack(self):
        """Identify sophisticated multi-stage attack patterns across different log sources."""
        if not self.events:
            return []

        # Convert to pandas DataFrame
        df = pd.DataFrame(self.events)

        # Ensure timestamp is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df = df.sort_values('timestamp')

        # Define multi-stage attack patterns
        attack_patterns = [
            {
                'name': 'Reconnaissance to Exploitation to Persistence',
                'stages': [
                    {'category': 'reconnaissance', 'rules': ['UA-.*', 'BF-SSH-.*'], 'min_count': 3},
                    {'category': 'exploitation', 'rules': ['PE-.*'], 'min_count': 1},
                    {'category': 'persistence', 'rules': ['MW-PERS-.*'], 'min_count': 1}
                ],
                'max_time_gap': 3600,  # 1 hour between stages
                'conditions': ['same_ip_address', 'same_username'],
                'severity': 'CRITICAL'
            },
            {
                'name': 'Data Exfiltration Campaign',
                'stages': [
                    {'category': 'access', 'rules': ['UA-.*'], 'min_count': 1},
                    {'category': 'internal_recon', 'rules': ['UA-FILE-.*'], 'min_count': 2},
                    {'category': 'exfiltration', 'rules': ['DE-.*'], 'min_count': 1}
                ],
                'max_time_gap': 7200,  # 2 hours between stages
                'conditions': ['same_ip_address'],
                'severity': 'HIGH'
            }
        ]

        # Find matches for each attack pattern
        multi_stage_attacks = []

        for pattern in attack_patterns:
            # Group by conditions if specified
            groupby_columns = []
            if 'same_ip_address' in pattern.get('conditions', []) and 'ip_address' in df.columns:
                groupby_columns.append('ip_address')
            if 'same_username' in pattern.get('conditions', []) and 'username' in df.columns:
                groupby_columns.append('username')

            # If no groupby columns, analyze all events together
            if not groupby_columns:
                matches = self._find_attack_stages(df, pattern)
                multi_stage_attacks.extend(matches)
            else:
                # Group events by specified columns
                for name, group in df.groupby(groupby_columns):
                    matches = self._find_attack_stages(group, pattern)
                    multi_stage_attacks.extend(matches)

        return multi_stage_attacks

    def _find_attack_stages(self, events_df, pattern):
        """Find events matching each stage of a multi-stage attack pattern."""
        matches = []
        stages_matched = []

        # Check each stage
        for stage in pattern['stages']:
            stage_events = []

            # Find events matching any rule pattern for this stage
            for rule_pattern in stage['rules']:
                matching_events = events_df[events_df['RULE_ID'].str.match(rule_pattern)]
                stage_events.extend(matching_events.to_dict('records'))

            # Check if we found enough events for this stage
            if len(stage_events) >= stage.get('min_count', 1):
                stages_matched.append({
                    'category': stage['category'],
                    'events': stage_events
                })

        # If all stages matched, check time constraints
        if len(stages_matched) == len(pattern['stages']):
            # Check if stages occurred in the expected order and within time constraints
            valid_sequence = True
            for i in range(1, len(stages_matched)):
                prev_time = max(pd.to_datetime(event['timestamp']) for event in stages_matched[i-1]['events'])
                curr_time = min(pd.to_datetime(event['timestamp']) for event in stages_matched[i]['events'])

                # Check if time gap between stages is too large
                if (curr_time - prev_time).total_seconds() > pattern.get('max_time_gap', float('inf')):
                    valid_sequence = False
                    break

            if valid_sequence:
                # Create a match record
                all_events = []
                for stage in stages_matched:
                    all_events.extend(stage['events'])

                # Sort by timestamp
                all_events.sort(key=lambda x: pd.to_datetime(x['timestamp']))

                matches.append({
                    'correlation_type': 'multi_stage_attack',
                    'attack_pattern': pattern['name'],
                    'event_count': len(all_events),
                    'events': all_events,
                    'start_time': all_events[0]['timestamp'],
                    'end_time': all_events[-1]['timestamp'],
                    'severity': pattern.get('severity', 'HIGH')
                })

        return matches
    
    def analyze_attack_velocity(self):
        """Analyze the velocity of attacks to identify coordinated campaigns."""
        if not self.events:
            return []

        # Convert to pandas DataFrame
        df = pd.DataFrame(self.events)

        # Ensure timestamp is datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df = df.sort_values('timestamp')

            # Calculate time differences between consecutive events
            df['time_diff'] = df['timestamp'].diff().dt.total_seconds()

            # Group by rule type to analyze patterns
            velocity_patterns = []

            # Extract rule categories (first 2-3 chars of rule ID)
            if 'RULE_ID' in df.columns:
                df['rule_category'] = df['RULE_ID'].str.extract(r'^([A-Z]{2,3})-')

                # Group by rule category
                for category, group in df.groupby('rule_category'):
                    if len(group) < 5:  # Skip if too few events
                        continue

                    # Calculate statistics
                    mean_interval = group['time_diff'].mean()
                    std_interval = group['time_diff'].std()
                    min_interval = group['time_diff'].min()

                    # Check for unusually regular patterns (potential automation)
                    if std_interval < mean_interval * 0.2 and len(group) > 10:
                        velocity_patterns.append({
                            'correlation_type': 'attack_velocity',
                            'category': category,
                            'event_count': len(group),
                            'mean_interval': float(mean_interval),
                            'std_interval': float(std_interval),
                            'min_interval': float(min_interval),
                            'start_time': str(group['timestamp'].min()),
                            'end_time': str(group['timestamp'].max()),
                            'events': group.to_dict('records'),
                            'severity': 'HIGH' if min_interval < 1.0 else 'MEDIUM'
                        })

            return velocity_patterns
        return []
    
    def save_checkpoint(self, checkpoint_id=None):
        """Save the current state for recovery.
        
        Args:
            checkpoint_id: Optional checkpoint identifier
            
        Returns:
            Checkpoint ID
        """
        if checkpoint_id is None:
            checkpoint_id = f"correlator_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
        checkpoint_dir = os.path.join(os.environ.get('IRF_ROOT', '.'), 'checkpoints')
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        # Save current state
        checkpoint_data = {
            'events': self.events,
            'correlation_window': self.correlation_window,
            'timestamp': datetime.now().isoformat()
        }
        
        checkpoint_file = os.path.join(checkpoint_dir, f"{checkpoint_id}.json")
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f, default=str)
            
        print(f"Created checkpoint: {checkpoint_id}")
        return checkpoint_id

    def restore_checkpoint(self, checkpoint_id):
        """Restore state from a checkpoint.
        
        Args:
            checkpoint_id: Checkpoint identifier
            
        Returns:
            True if successful, False otherwise
        """
        checkpoint_dir = os.path.join(os.environ.get('IRF_ROOT', '.'), 'checkpoints')
        checkpoint_file = os.path.join(checkpoint_dir, f"{checkpoint_id}.json")
        
        if not os.path.exists(checkpoint_file):
            print(f"Checkpoint not found: {checkpoint_id}")
            return False
            
        try:
            with open(checkpoint_file, 'r') as f:
                checkpoint_data = json.load(f)
                
            self.events = checkpoint_data.get('events', [])
            self.correlation_window = checkpoint_data.get('correlation_window', 300)
            
            print(f"Restored checkpoint: {checkpoint_id}")
            return True
        except Exception as e:
            print(f"Error restoring checkpoint: {e}")
            return False
    
    def _find_attack_chain(self, df, pattern):
        """Legacy method for backward compatibility."""
        # This method is kept for backward compatibility
        # New code should use pattern_engine directly
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
        multi_stage_correlations = self.correlate_multi_stage_attack()
        velocity_correlations = self.analyze_attack_velocity()
        
        correlations.extend(ip_correlations)
        correlations.extend(time_correlations)
        correlations.extend(chain_correlations)
        correlations.extend(multi_stage_correlations)
        correlations.extend(velocity_correlations)
        
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