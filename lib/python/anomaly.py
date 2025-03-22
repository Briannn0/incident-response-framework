#!/usr/bin/env python3
#
# Statistical anomaly detection module for the Incident Response Framework
# This module helps find unusual or suspicious patterns in log data
# (An anomaly is something that doesn't follow the normal pattern)

# Standard library imports - these are built into Python
import os                  # For working with files and directories
import sys                 # For system-specific functions
import json                # For working with JSON data format
import traceback           # For detailed error information

# Data processing imports - these help analyze and manipulate data
import pandas as pd        # For data tables (like Excel spreadsheets)
import numpy as np         # For numerical calculations

# Statistical analysis imports - these help find unusual patterns
from scipy import stats    # For statistical calculations
from sklearn.ensemble import IsolationForest  # A method to find outliers
from sklearn.cluster import DBSCAN            # A method to group similar data

# Add our other modules to Python's search path
# This allows us to import other modules from our project
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

class AnomalyDetector:
    """A tool that helps find unusual patterns in data."""
    
    def __init__(self, config=None):
        """Start the detector with optional settings.
        
        Args:
            config: A dictionary with settings (like which column has timestamps)
                   If None, we'll use default settings.
        """
        self.config = config or {}  # If no config provided, use empty dictionary
        self.data = None            # We'll store the data here once loaded
        self.time_field = self.config.get('time_field', 'timestamp')  # Column name for time values
    
    @handle_errors
    def load_data(self, data_file, format='csv'):
        """Read data from a file into memory so we can analyze it.
        
        Args:
            data_file: Path to the file containing the data
            format: The type of file ('csv', 'tsv', or 'json')
                   CSV = Comma Separated Values
                   TSV = Tab Separated Values
                   JSON = JavaScript Object Notation
        
        Returns:
            True if data loaded successfully, False otherwise
        """
        try:
            # Load the data based on the file format
            if format == 'csv':
                self.data = pd.read_csv(data_file)  # Read comma-separated data
            elif format == 'tsv':
                self.data = pd.read_csv(data_file, sep='\t')  # Read tab-separated data
            elif format == 'json':
                self.data = pd.read_json(data_file)  # Read JSON formatted data
            else:
                raise ValueError(f"Unsupported format: {format}")  # Report unsupported format
            
            # Convert timestamp to datetime
            if self.time_field in self.data.columns:
                self.data[self.time_field] = pd.to_datetime(self.data[self.time_field], errors='coerce')
                
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    @handle_errors
    def detect_statistical_anomalies(self, fields, output_file=None):
        """Detect anomalies based on statistical methods.
        
        Args:
            fields: List of column names to analyze
            output_file: Path to save the results (optional)
        
        Returns:
            Dictionary with anomaly details
        """
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
    
    @handle_errors
    def detect_isolation_forest_anomalies(self, fields, contamination=0.05, output_file=None):
        """Detect anomalies using Isolation Forest algorithm.
        
        Args:
            fields: List of column names to analyze
            contamination: Proportion of outliers in the data
            output_file: Path to save the results (optional)
        
        Returns:
            Dictionary with anomaly details
        """
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
    
    @handle_errors
    def detect_dbscan_anomalies(self, fields, eps=0.5, min_samples=5, output_file=None):
        """Detect anomalies using DBSCAN clustering algorithm.
        
        Args:
            fields: List of column names to analyze
            eps: Maximum distance between two samples for them to be considered as in the same neighborhood
            min_samples: Number of samples in a neighborhood for a point to be considered as a core point
            output_file: Path to save the results (optional)
        
        Returns:
            Dictionary with anomaly details
        """
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
    
    @handle_errors
    def run_all_detections(self, fields, output_file=None):
        """Run all anomaly detection methods.
        
        Args:
            fields: List of column names to analyze
            output_file: Path to save the results (optional)
        
        Returns:
            Dictionary with combined anomaly details
        """
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
    
    try:
        detector = AnomalyDetector()
        
        if not detector.load_data(args.data, args.format):
            error_info = {
                "status": "error",
                "error_type": "DataLoadError",
                "error_message": "Failed to load data."
            }
            sys.stderr.write(json.dumps(error_info) + "\n")
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
    except Exception as e:
        error_info = {
            "status": "error",
            "error_type": type(e).__name__,
            "error_message": str(e)
        }
        sys.stderr.write(json.dumps(error_info) + "\n")
        sys.exit(1)