#!/usr/bin/env python3
#
# Statistical anomaly detection module for the Incident Response Framework
# Provides methods to identify unusual patterns in log data

import os
import sys
import json
import pandas as pd
import numpy as np
from scipy import stats
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN

# Add path for other IRF modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AnomalyDetector:
    def __init__(self, config=None):
        """Initialize the anomaly detector with optional configuration."""
        self.config = config or {}
        self.data = None
        self.time_field = self.config.get('time_field', 'timestamp')
        
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
    
    def detect_statistical_anomalies(self, fields, output_file=None):
        """Detect anomalies based on statistical methods."""
        if self.data is None:
            return None
            
        results = {}
        anomalies = []
        
        # Process each field
        for field in fields:
            if field not in self.data.columns:
                continue
                
            field_data = self.data[field]
            
            # Skip non-numeric fields
            if not np.issubdtype(field_data.dtype, np.number):
                continue
                
            # Calculate z-scores
            z_scores = np.abs(stats.zscore(field_data, nan_policy='omit'))
            
            # Find anomalies where z-score > 3
            anomaly_indices = np.where(z_scores > 3)[0]
            
            if len(anomaly_indices) > 0:
                for idx in anomaly_indices:
                    if idx < len(self.data):
                        row = self.data.iloc[idx].to_dict()
                        anomalies.append({
                            'method': 'z_score',
                            'field': field,
                            'value': float(field_data.iloc[idx]),
                            'z_score': float(z_scores[idx]),
                            'timestamp': str(row.get(self.time_field, '')),
                            'row_data': row
                        })
        
        results['statistical_anomalies'] = {
            'count': len(anomalies),
            'anomalies': anomalies
        }
        
        # Save results if output file provided
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        return results
    
    def detect_isolation_forest_anomalies(self, fields, contamination=0.05, output_file=None):
        """Detect anomalies using Isolation Forest algorithm."""
        if self.data is None:
            return None
            
        # Prepare data for Isolation Forest
        numeric_data = self.data[fields].select_dtypes(include=[np.number])
        
        # Skip if no numeric fields
        if numeric_data.empty:
            print("No numeric fields available for Isolation Forest")
            return None
        
        # Fill NaN values with mean
        numeric_data = numeric_data.fillna(numeric_data.mean())
        
        # Apply Isolation Forest
        model = IsolationForest(contamination=contamination, random_state=42)
        predictions = model.fit_predict(numeric_data)
        
        # Find anomalies (predictions == -1)
        anomaly_indices = np.where(predictions == -1)[0]
        anomalies = []
        
        for idx in anomaly_indices:
            if idx < len(self.data):
                row = self.data.iloc[idx].to_dict()
                anomalies.append({
                    'method': 'isolation_forest',
                    'anomaly_score': float(model.score_samples(numeric_data.iloc[idx:idx+1])[0]),
                    'timestamp': str(row.get(self.time_field, '')),
                    'row_data': row
                })
        
        results = {
            'isolation_forest_anomalies': {
                'count': len(anomalies),
                'contamination': contamination,
                'anomalies': anomalies
            }
        }
        
        # Save results if output file provided
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        return results
    
    def detect_dbscan_anomalies(self, fields, eps=0.5, min_samples=5, output_file=None):
        """Detect anomalies using DBSCAN clustering algorithm."""
        if self.data is None:
            return None
            
        # Prepare data for DBSCAN
        numeric_data = self.data[fields].select_dtypes(include=[np.number])
        
        # Skip if no numeric fields
        if numeric_data.empty:
            print("No numeric fields available for DBSCAN")
            return None
        
        # Fill NaN values with mean
        numeric_data = numeric_data.fillna(numeric_data.mean())
        
        # Normalize data for better clustering
        from sklearn.preprocessing import StandardScaler
        scaled_data = StandardScaler().fit_transform(numeric_data)
        
        # Apply DBSCAN
        dbscan = DBSCAN(eps=eps, min_samples=min_samples)
        clusters = dbscan.fit_predict(scaled_data)
        
        # Find anomalies (clusters == -1)
        anomaly_indices = np.where(clusters == -1)[0]
        anomalies = []
        
        for idx in anomaly_indices:
            if idx < len(self.data):
                row = self.data.iloc[idx].to_dict()
                anomalies.append({
                    'method': 'dbscan',
                    'timestamp': str(row.get(self.time_field, '')),
                    'row_data': row
                })
        
        results = {
            'dbscan_anomalies': {
                'count': len(anomalies),
                'params': {
                    'eps': eps,
                    'min_samples': min_samples
                },
                'anomalies': anomalies
            }
        }
        
        # Save results if output file provided
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        return results
    
    def run_all_detections(self, fields, output_file=None):
        """Run all anomaly detection methods."""
        if self.data is None:
            return None
            
        results = {}
        
        # Run statistical anomaly detection
        stat_results = self.detect_statistical_anomalies(fields)
        if stat_results:
            results.update(stat_results)
        
        # Run Isolation Forest
        if_results = self.detect_isolation_forest_anomalies(fields)
        if if_results:
            results.update(if_results)
        
        # Run DBSCAN
        dbscan_results = self.detect_dbscan_anomalies(fields)
        if dbscan_results:
            results.update(dbscan_results)
        
        # Calculate overall stats
        total_anomalies = 0
        for method, method_results in results.items():
            total_anomalies += method_results.get('count', 0)
        
        results['summary'] = {
            'total_anomalies': total_anomalies,
            'methods_used': list(results.keys())
        }
        
        # Save results if output file provided
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        return results

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='IRF Anomaly Detector')
    parser.add_argument('--data', required=True, help='Path to data file')
    parser.add_argument('--format', default='tsv', choices=['csv', 'tsv', 'json'], help='Data file format')
    parser.add_argument('--output', required=True, help='Path to output file')
    parser.add_argument('--fields', required=True, help='Comma-separated list of fields to analyze')
    parser.add_argument('--method', default='all', choices=['statistical', 'isolation_forest', 'dbscan', 'all'], 
                        help='Anomaly detection method to use')
    
    args = parser.parse_args()
    
    detector = AnomalyDetector()
    
    if not detector.load_data(args.data, args.format):
        print("Failed to load data.")
        sys.exit(1)
    
    fields = args.fields.split(',')
    
    if args.method == 'statistical' or args.method == 'all':
        detector.detect_statistical_anomalies(fields, args.output)
        print(f"Statistical anomaly detection complete. Results saved to {args.output}")
    
    if args.method == 'isolation_forest' or args.method == 'all':
        detector.detect_isolation_forest_anomalies(fields, output_file=args.output)
        print(f"Isolation Forest anomaly detection complete. Results saved to {args.output}")
    
    if args.method == 'dbscan' or args.method == 'all':
        detector.detect_dbscan_anomalies(fields, output_file=args.output)
        print(f"DBSCAN anomaly detection complete. Results saved to {args.output}")
    
    if args.method == 'all':
        results = detector.run_all_detections(fields, args.output)
        print(f"All anomaly detection methods complete. Found {results['summary']['total_anomalies']} anomalies.")
        print(f"Results saved to {args.output}")