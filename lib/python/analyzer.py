#!/usr/bin/env python3
#
# Statistical analysis module for the Incident Response Framework
# Provides time-based analysis and anomaly detection

import os
import sys
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from scipy import stats

# Add path for other IRF modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TimeSeriesAnalyzer:
    def __init__(self, config=None):
        """Initialize the analyzer with optional configuration."""
        self.config = config or {}
        self.data = None
        self.time_field = self.config.get('time_field', 'timestamp')
        self.fig_path = self.config.get('figures_path', os.path.join(os.environ.get('IRF_ROOT', '.'), 'evidence/analysis'))
        
        # Create figures directory if it doesn't exist
        if not os.path.exists(self.fig_path):
            os.makedirs(self.fig_path, exist_ok=True)
        
    def load_data(self, data_file, format='csv'):
        """Load data from a file."""
        try:
            if format == 'csv':
                self.data = pd.read_csv(data_file)
            elif format == 'tsv':
                self.data = pd.read_csv(data_file, sep='\t')
            elif format == 'json':
                self.data = pd.read_json(data_file)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Convert timestamp to datetime
            if self.time_field in self.data.columns:
                self.data[self.time_field] = pd.to_datetime(self.data[self.time_field], errors='coerce')
                
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def event_frequency_analysis(self, groupby='1H', output_file=None):
        """Analyze event frequency over time."""
        if self.data is None or self.time_field not in self.data.columns:
            return None
        
        # Ensure timestamp is the index
        df = self.data.set_index(self.time_field)
        
        # Count events per time interval
        event_counts = df.resample(groupby).size()
        
        # Calculate statistics
        stats = {
            'total_events': int(event_counts.sum()),
            'mean_events_per_period': float(event_counts.mean()),
            'std_events_per_period': float(event_counts.std()),
            'max_events_per_period': int(event_counts.max()),
            'max_events_timestamp': str(event_counts.idxmax())
        }
        
        # Generate visualization
        plt.figure(figsize=(12, 6))
        event_counts.plot(title=f'Event Frequency (grouped by {groupby})')
        plt.xlabel('Time')
        plt.ylabel('Event Count')
        plt.grid(True)
        
        # Save figure
        fig_file = os.path.join(self.fig_path, f'event_frequency_{groupby}.png')
        plt.savefig(fig_file)
        
        # Save stats if output file provided
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(stats, f, indent=2)
        
        return {
            'stats': stats,
            'figure': fig_file,
            'data': event_counts.to_dict()
        }
    
    def detect_activity_spikes(self, threshold=2.0, output_file=None):
        """Detect unusual spikes in activity."""
        if self.data is None or self.time_field not in self.data.columns:
            return None
        
        # Ensure timestamp is the index
        df = self.data.set_index(self.time_field)
        
        # Count events per minute
        event_counts = df.resample('1min').size().fillna(0)
        
        # Calculate Z-scores
        mean = event_counts.mean()
        std = event_counts.std()
        z_scores = (event_counts - mean) / std
        
        # Identify spikes above threshold
        spikes = event_counts[z_scores > threshold]
        
        # Format results
        spike_data = []
        for time, count in spikes.items():
            spike_data.append({
                'timestamp': str(time),
                'count': int(count),
                'z_score': float(z_scores[time]),
                'deviation_from_mean': float(count - mean)
            })
        
        # Generate visualization
        plt.figure(figsize=(12, 6))
        event_counts.plot(label='Event Count')
        if len(spikes) > 0:
            spikes.plot(style='ro', label='Detected Spikes')
        plt.axhline(y=mean, color='g', linestyle='-', label='Mean')
        plt.axhline(y=mean + threshold*std, color='r', linestyle='--', label=f'Threshold (mean + {threshold}σ)')
        plt.title('Activity Spike Detection')
        plt.xlabel('Time')
        plt.ylabel('Event Count')
        plt.legend()
        plt.grid(True)
        
        # Save figure
        fig_file = os.path.join(self.fig_path, 'activity_spikes.png')
        plt.savefig(fig_file)
        
        # Save results if output file provided
        results = {
            'threshold': threshold,
            'mean_activity': float(mean),
            'std_activity': float(std),
            'num_spikes_detected': len(spike_data),
            'spikes': spike_data,
            'figure': fig_file
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        return results
    
    def attack_sequence_analysis(self, rule_field='RULE_ID', min_sequence=3, max_gap=300, output_file=None):
        """Identify potential attack sequences based on rule patterns and timing."""
        if self.data is None or self.time_field not in self.data.columns or rule_field not in self.data.columns:
            return None
        
        # Ensure data is sorted by timestamp
        df = self.data.sort_values(self.time_field)
        
        # Extract rule types (first 2 characters of rule ID)
        if rule_field in df.columns:
            df['rule_type'] = df[rule_field].str[:3]
        
        # Initialize sequence detection
        sequences = []
        current_seq = []
        
        # Iterate through events chronologically
        for i, row in df.iterrows():
            if not current_seq:
                current_seq = [row.to_dict()]
            else:
                last_time = pd.to_datetime(current_seq[-1][self.time_field])
                current_time = pd.to_datetime(row[self.time_field])
                
                # Check if this event is within the time window of the previous event
                if (current_time - last_time).total_seconds() <= max_gap:
                    current_seq.append(row.to_dict())
                else:
                    # End of sequence, check if it meets minimum length
                    if len(current_seq) >= min_sequence:
                        # Check if sequence has at least 2 different rule types
                        rule_types = set(e.get('rule_type', '') for e in current_seq)
                        if len(rule_types) >= 2:
                            sequences.append({
                                'start_time': str(current_seq[0][self.time_field]),
                                'end_time': str(current_seq[-1][self.time_field]),
                                'duration_seconds': (pd.to_datetime(current_seq[-1][self.time_field]) - 
                                                    pd.to_datetime(current_seq[0][self.time_field])).total_seconds(),
                                'num_events': len(current_seq),
                                'rule_types': list(rule_types),
                                'events': current_seq
                            })
                    # Start a new sequence
                    current_seq = [row.to_dict()]
        
        # Check the last sequence
        if len(current_seq) >= min_sequence:
            rule_types = set(e.get('rule_type', '') for e in current_seq)
            if len(rule_types) >= 2:
                sequences.append({
                    'start_time': str(current_seq[0][self.time_field]),
                    'end_time': str(current_seq[-1][self.time_field]),
                    'duration_seconds': (pd.to_datetime(current_seq[-1][self.time_field]) - 
                                        pd.to_datetime(current_seq[0][self.time_field])).total_seconds(),
                    'num_events': len(current_seq),
                    'rule_types': list(rule_types),
                    'events': current_seq
                })
        
        # Save results if output file provided
        results = {
            'parameters': {
                'min_sequence_length': min_sequence,
                'max_event_gap_seconds': max_gap
            },
            'num_sequences_detected': len(sequences),
            'sequences': sequences
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        return results

class BaselineProfiler:
    def __init__(self, config=None):
        """Initialize the baseline profiler with optional configuration."""
        self.config = config or {}
        self.data = None
        self.time_field = self.config.get('time_field', 'timestamp')
        self.baseline_period = self.config.get('baseline_period', '7D')  # Default 7 days
        self.profiles = {}
        
    def load_data(self, data_file, format='csv'):
        """Load data from a file."""
        try:
            if format == 'csv':
                self.data = pd.read_csv(data_file)
            elif format == 'tsv':
                self.data = pd.read_csv(data_file, sep='\t')
            elif format == 'json':
                self.data = pd.read_json(data_file)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Convert timestamp to datetime
            if self.time_field in self.data.columns:
                self.data[self.time_field] = pd.to_datetime(self.data[self.time_field], errors='coerce')
                
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def create_time_profiles(self, groupby=['hour', 'dayofweek']):
        """Create baseline profiles based on time patterns."""
        if self.data is None or self.time_field not in self.data.columns:
            return None
        
        # Ensure timestamp is a datetime
        df = self.data.copy()
        df[self.time_field] = pd.to_datetime(df[self.time_field])
        
        # Extract time components
        df['hour'] = df[self.time_field].dt.hour
        df['dayofweek'] = df[self.time_field].dt.dayofweek  # 0=Monday, 6=Sunday
        df['day'] = df[self.time_field].dt.day
        df['month'] = df[self.time_field].dt.month
        
        profiles = {}
        
        # Create profiles based on specified groupings
        for group in groupby:
            if group == 'hour':
                # Hourly profile (0-23)
                hourly_counts = df.groupby('hour').size()
                hourly_stats = df.groupby('hour').size().describe()
                profiles['hourly'] = {
                    'counts': hourly_counts.to_dict(),
                    'stats': {
                        'mean': float(hourly_stats['mean']),
                        'std': float(hourly_stats['std']),
                        'min': float(hourly_stats['min']),
                        'max': float(hourly_stats['max']),
                        'thresholds': {
                            'low': float(hourly_stats['mean'] - 2*hourly_stats['std']),
                            'high': float(hourly_stats['mean'] + 2*hourly_stats['std'])
                        }
                    }
                }
                
            elif group == 'dayofweek':
                # Day of week profile (0=Monday, 6=Sunday)
                dow_counts = df.groupby('dayofweek').size()
                dow_stats = df.groupby('dayofweek').size().describe()
                profiles['dayofweek'] = {
                    'counts': dow_counts.to_dict(),
                    'stats': {
                        'mean': float(dow_stats['mean']),
                        'std': float(dow_stats['std']),
                        'min': float(dow_stats['min']),
                        'max': float(dow_stats['max']),
                        'thresholds': {
                            'low': float(dow_stats['mean'] - 2*dow_stats['std']),
                            'high': float(dow_stats['mean'] + 2*dow_stats['std'])
                        }
                    }
                }
                
            elif group == 'hour_dayofweek':
                # Hour by day of week profile
                hd_counts = df.groupby(['dayofweek', 'hour']).size().unstack(fill_value=0)
                profiles['hour_dayofweek'] = {
                    'counts': {str(day): {str(hour): count for hour, count in day_data.items()} 
                              for day, day_data in hd_counts.to_dict().items()},
                    'stats': {
                        'mean': float(hd_counts.values.mean()),
                        'std': float(hd_counts.values.std()),
                        'min': float(hd_counts.values.min()),
                        'max': float(hd_counts.values.max()),
                        'thresholds': {
                            'low': float(hd_counts.values.mean() - 2*hd_counts.values.std()),
                            'high': float(hd_counts.values.mean() + 2*hd_counts.values.std())
                        }
                    }
                }
        
        self.profiles = profiles
        return profiles
    
    def create_user_profiles(self, user_field='username'):
        """Create baseline profiles based on user behavior."""
        if self.data is None or self.time_field not in self.data.columns or user_field not in self.data.columns:
            return None
        
        # Ensure timestamp is a datetime
        df = self.data.copy()
        df[self.time_field] = pd.to_datetime(df[self.time_field])
        
        # Extract time components
        df['hour'] = df[self.time_field].dt.hour
        df['dayofweek'] = df[self.time_field].dt.dayofweek
        
        # Filter out empty usernames
        df = df[df[user_field].notna() & (df[user_field] != '')]
        
        # Group by user
        user_profiles = {}
        
        for user, user_data in df.groupby(user_field):
            # Skip if less than 10 events for this user
            if len(user_data) < 10:
                continue
                
            # User's active hours
            active_hours = user_data.groupby('hour').size()
            active_hours_mean = active_hours.mean()
            active_hours_std = active_hours.std()
            
            # User's active days
            active_days = user_data.groupby('dayofweek').size()
            active_days_mean = active_days.mean()
            active_days_std = active_days.std()
            
            # Most common source IPs if available
            source_ips = {}
            if 'ip_address' in user_data.columns:
                source_ips = user_data['ip_address'].value_counts().to_dict()
            
            user_profiles[user] = {
                'event_count': len(user_data),
                'active_hours': {
                    'counts': active_hours.to_dict(),
                    'mean': float(active_hours_mean),
                    'std': float(active_hours_std),
                    'thresholds': {
                        'high': float(active_hours_mean + 2*active_hours_std) if not np.isnan(active_hours_std) else None
                    }
                },
                'active_days': {
                    'counts': active_days.to_dict(),
                    'mean': float(active_days_mean),
                    'std': float(active_days_std),
                    'thresholds': {
                        'high': float(active_days_mean + 2*active_days_std) if not np.isnan(active_days_std) else None
                    }
                },
                'source_ips': source_ips
            }
        
        self.profiles['users'] = user_profiles
        return user_profiles
    
    def detect_anomalies(self, new_data_file, format='tsv', output_file=None):
        """Detect anomalies by comparing new data against baseline profiles."""
        if not self.profiles:
            print("No baseline profiles available. Create profiles first.")
            return None
        
        # Load new data
        try:
            if format == 'csv':
                new_data = pd.read_csv(new_data_file)
            elif format == 'tsv':
                new_data = pd.read_csv(new_data_file, sep='\t')
            elif format == 'json':
                new_data = pd.read_json(new_data_file)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
            # Convert timestamp to datetime
            if self.time_field in new_data.columns:
                new_data[self.time_field] = pd.to_datetime(new_data[self.time_field], errors='coerce')
        except Exception as e:
            print(f"Error loading new data: {e}")
            return None
        
        # Extract time components from new data
        new_df = new_data.copy()
        new_df['hour'] = new_df[self.time_field].dt.hour
        new_df['dayofweek'] = new_df[self.time_field].dt.dayofweek
        
        anomalies = []
        
        # Check hourly patterns if available
        if 'hourly' in self.profiles:
            hourly_profile = self.profiles['hourly']
            hourly_counts = new_df.groupby('hour').size()
            
            for hour, count in hourly_counts.items():
                if hour in hourly_profile['counts'] and count > hourly_profile['stats']['thresholds']['high']:
                    anomalies.append({
                        'type': 'hourly_activity',
                        'hour': int(hour),
                        'count': int(count),
                        'expected_max': float(hourly_profile['stats']['thresholds']['high']),
                        'severity': 'MEDIUM' if count < hourly_profile['stats']['max'] * 2 else 'HIGH'
                    })
        
        # Check day of week patterns if available
        if 'dayofweek' in self.profiles:
            dow_profile = self.profiles['dayofweek']
            dow_counts = new_df.groupby('dayofweek').size()
            
            for day, count in dow_counts.items():
                if day in dow_profile['counts'] and count > dow_profile['stats']['thresholds']['high']:
                    anomalies.append({
                        'type': 'dayofweek_activity',
                        'day': int(day),
                        'day_name': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'][int(day)],
                        'count': int(count),
                        'expected_max': float(dow_profile['stats']['thresholds']['high']),
                        'severity': 'MEDIUM' if count < dow_profile['stats']['max'] * 2 else 'HIGH'
                    })
        
        # Check user behavior if available
        if 'users' in self.profiles and 'username' in new_df.columns:
            # Group by username
            for username, user_data in new_df.groupby('username'):
                if username in self.profiles['users']:
                    user_profile = self.profiles['users'][username]
                    
                    # Check for unusual hours
                    user_hours = user_data.groupby('hour').size()
                    for hour, count in user_hours.items():
                        hour_threshold = user_profile['active_hours']['thresholds']['high']
                        if hour_threshold and count > hour_threshold:
                            anomalies.append({
                                'type': 'user_hourly_activity',
                                'username': username,
                                'hour': int(hour),
                                'count': int(count),
                                'expected_max': float(hour_threshold),
                                'severity': 'MEDIUM'
                            })
                    
                    # Check for unusual source IPs
                    if 'ip_address' in user_data.columns and 'source_ips' in user_profile:
                        known_ips = list(user_profile['source_ips'].keys())
                        unknown_ips = user_data[~user_data['ip_address'].isin(known_ips)]['ip_address'].unique()
                        
                        for ip in unknown_ips:
                            if ip and str(ip) != 'nan':
                                anomalies.append({
                                    'type': 'user_unknown_ip',
                                    'username': username,
                                    'ip_address': str(ip),
                                    'known_ips': known_ips[:5],  # List first 5 known IPs
                                    'severity': 'HIGH'
                                })
        
        # Save results if output file provided
        results = {
            'total_anomalies': len(anomalies),
            'anomalies': anomalies
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        return results
    
    def save_profiles(self, output_file):
        """Save baseline profiles to a file."""
        if not self.profiles:
            print("No profiles to save.")
            return False
            
        try:
            with open(output_file, 'w') as f:
                json.dump(self.profiles, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving profiles: {e}")
            return False
    
    def load_profiles(self, profiles_file):
        """Load baseline profiles from a file."""
        try:
            with open(profiles_file, 'r') as f:
                self.profiles = json.load(f)
            return True
        except Exception as e:
            print(f"Error loading profiles: {e}")
            return False

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='IRF Time Series and Baseline Analyzer')
    parser.add_argument('--data', required=True, help='Path to data file')
    parser.add_argument('--format', default='tsv', choices=['csv', 'tsv', 'json'], help='Data file format')
    parser.add_argument('--output', required=True, help='Path to output directory')
    parser.add_argument('--time-field', default='timestamp', help='Name of timestamp field')
    
    # Create subparsers for different analysis types
    subparsers = parser.add_subparsers(dest='analysis_type', help='Type of analysis to perform')
    
    # Time series analysis parser
    ts_parser = subparsers.add_parser('timeseries', help='Time series analysis')
    ts_parser.add_argument('--analysis', required=True, choices=['frequency', 'spikes', 'sequences', 'all'], 
                        help='Type of time series analysis to perform')
    ts_parser.add_argument('--groupby', default='1H', help='Time grouping for frequency analysis')
    ts_parser.add_argument('--threshold', type=float, default=2.0, help='Z-score threshold for spike detection')
    ts_parser.add_argument('--min-sequence', type=int, default=3, help='Minimum events for sequence detection')
    ts_parser.add_argument('--max-gap', type=int, default=300, help='Maximum seconds between events in a sequence')
    
    # Baseline profiling parser
    baseline_parser = subparsers.add_parser('baseline', help='Baseline profiling and anomaly detection')
    baseline_parser.add_argument('--action', required=True, 
                              choices=['create', 'detect', 'save', 'load'], 
                              help='Baseline profiling action')
    baseline_parser.add_argument('--profile-type', choices=['time', 'user', 'both'], 
                              default='both', help='Type of profile to create')
    baseline_parser.add_argument('--user-field', default='username', help='Field containing username')
    baseline_parser.add_argument('--time-groups', default='hour,dayofweek,hour_dayofweek', 
                              help='Time groupings for profiling (comma-separated)')
    baseline_parser.add_argument('--profile-file', help='File to save/load baseline profiles')
    baseline_parser.add_argument('--comparison-data', help='Data file to compare against baseline')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    if args.analysis_type == 'timeseries':
        analyzer = TimeSeriesAnalyzer({
            'time_field': args.time_field,
            'figures_path': args.output
        })
        
        if not analyzer.load_data(args.data, args.format):
            print("Failed to load data.")
            sys.exit(1)
        
        # Run requested analysis
        if args.analysis == 'frequency' or args.analysis == 'all':
            output_file = os.path.join(args.output, 'frequency_analysis.json')
            result = analyzer.event_frequency_analysis(args.groupby, output_file)
            print(f"Frequency analysis complete. Results saved to {output_file}")
            print(f"Figure saved to {result['figure']}")
        
        if args.analysis == 'spikes' or args.analysis == 'all':
            output_file = os.path.join(args.output, 'spike_detection.json')
            result = analyzer.detect_activity_spikes(args.threshold, output_file)
            print(f"Spike detection complete. Found {result['num_spikes_detected']} spikes.")
            print(f"Results saved to {output_file}")
            print(f"Figure saved to {result['figure']}")
        
        if args.analysis == 'sequences' or args.analysis == 'all':
            output_file = os.path.join(args.output, 'sequence_analysis.json')
            result = analyzer.attack_sequence_analysis('RULE_ID', args.min_sequence, args.max_gap, output_file)
            print(f"Sequence analysis complete. Detected {result['num_sequences_detected']} potential attack sequences.")
            print(f"Results saved to {output_file}")
    
    elif args.analysis_type == 'baseline':
        profiler = BaselineProfiler({
            'time_field': args.time_field
        })
        
        if args.action == 'create':
            if not profiler.load_data(args.data, args.format):
                print("Failed to load data.")
                sys.exit(1)
            
            if args.profile_type in ['time', 'both']:
                time_groups = args.time_groups.split(',')
                profiles = profiler.create_time_profiles(time_groups)
                print(f"Created time-based profiles with {len(profiles)} groupings.")
            
            if args.profile_type in ['user', 'both']:
                user_profiles = profiler.create_user_profiles(args.user_field)
                if user_profiles:
                    print(f"Created user profiles for {len(user_profiles)} users.")
                else:
                    print("No user profiles created. Check that data contains user information.")
            
            if args.profile_file:
                if profiler.save_profiles(args.profile_file):
                    print(f"Saved profiles to {args.profile_file}")
                else:
                    print("Failed to save profiles.")
        
        elif args.action == 'load':
            if not args.profile_file:
                print("Error: --profile-file is required for loading profiles.")
                sys.exit(1)
                
            if profiler.load_profiles(args.profile_file):
                print(f"Loaded profiles from {args.profile_file}")
            else:
                print("Failed to load profiles.")
                sys.exit(1)
        
        elif args.action == 'save':
            if not args.profile_file:
                print("Error: --profile-file is required for saving profiles.")
                sys.exit(1)
                
            if not profiler.profiles:
                print("No profiles to save. Create profiles first.")
                sys.exit(1)
                
            if profiler.save_profiles(args.profile_file):
                print(f"Saved profiles to {args.profile_file}")
            else:
                print("Failed to save profiles.")
        
        elif args.action == 'detect':
            if not args.comparison_data:
                print("Error: --comparison-data is required for anomaly detection.")
                sys.exit(1)
                
            if not profiler.profiles and args.profile_file:
                if not profiler.load_profiles(args.profile_file):
                    print("Failed to load profiles.")
                    sys.exit(1)
            
            if not profiler.profiles:
                print("No profiles available. Load or create profiles first.")
                sys.exit(1)
                
            output_file = os.path.join(args.output, 'anomaly_detection.json')
            results = profiler.detect_anomalies(args.comparison_data, args.format, output_file)
            
            # Process the anomaly detection results
            if results:
                # Print a summary of the findings to the console
                print(f"Anomaly detection complete. Found {results['total_anomalies']} anomalies.")
                print(f"Results saved to {output_file}")
                
                # If there are anomalies found, provide additional information
                if results['total_anomalies'] > 0:
                    print("\nSummary of anomalies found:")
                    print("---------------------------")
                    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
                    
                    # Count anomalies by severity level
                    for anomaly in results['anomalies']:
                        severity = anomaly.get('severity', 'MEDIUM')
                        severity_count[severity] += 1
                    
                    # Print the severity breakdown
                    print(f"HIGH severity: {severity_count['HIGH']}")
                    print(f"MEDIUM severity: {severity_count['MEDIUM']}")
                    print(f"LOW severity: {severity_count['LOW']}")
                    print("\nReview the output file for complete details on each anomaly.")
                    print("Anomalies indicate unusual patterns that may require investigation.")
            else:
                print("Anomaly detection failed. Check that your data and profiles are valid.")
    else:
        # Show help if no valid analysis type was selected
        parser.print_help()