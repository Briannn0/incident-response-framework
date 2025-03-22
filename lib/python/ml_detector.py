#!/usr/bin/env python3
"""
Machine Learning detection module for the Incident Response Framework
Implements anomaly detection and threat classification using ML techniques
"""

import os
import sys
import json
import pandas as pd
import numpy as np
import pickle
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

class MLDetector:
    def __init__(self, config=None):
        """Initialize the ML detector with optional configuration"""
        self.config = config or {}
        self.models = {}
        self.models_dir = self.config.get('models_dir') or os.path.join(
            os.environ.get('IRF_ROOT', '.'), 'models')
            
        # Create models directory if it doesn't exist
        if not os.path.exists(self.models_dir):
            os.makedirs(self.models_dir, exist_ok=True)
            
    def load_data(self, data_file, format='tsv'):
        """Load data from a file"""
        if format == 'tsv':
            return pd.read_csv(data_file, sep='\t')
        elif format == 'csv':
            return pd.read_csv(data_file)
        elif format == 'json':
            return pd.read_json(data_file)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def preprocess_data(self, data, numeric_fields=None, categorical_fields=None, 
                       text_fields=None, timestamp_field='timestamp'):
        """Preprocess data for ML algorithms"""
        df = data.copy()
        
        # Handle timestamp
        if timestamp_field in df.columns:
            if df[timestamp_field].dtype != 'datetime64[ns]':
                df[timestamp_field] = pd.to_datetime(df[timestamp_field], errors='coerce')
                
            # Extract time features
            df['hour'] = df[timestamp_field].dt.hour
            df['day_of_week'] = df[timestamp_field].dt.dayofweek
            df['is_weekend'] = df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
        
        # Process numeric fields
        X_numeric = None
        if numeric_fields:
            # Select numeric fields and fill missing values
            num_df = df[numeric_fields].copy()
            num_df = num_df.fillna(num_df.mean())
            
            # Scale numeric features
            scaler = StandardScaler()
            X_numeric = scaler.fit_transform(num_df)
            
            # Save scaler for later use
            with open(os.path.join(self.models_dir, 'scaler.pkl'), 'wb') as f:
                pickle.dump(scaler, f)
        
        # Process categorical fields
        X_categorical = None
        if categorical_fields:
            # One-hot encode categorical variables
            cat_df = pd.get_dummies(df[categorical_fields], drop_first=True)
            X_categorical = cat_df.values
            
            # Save category mapping
            with open(os.path.join(self.models_dir, 'categorical_columns.json'), 'w') as f:
                json.dump(list(cat_df.columns), f)
        
        # Process text fields
        X_text = None
        if text_fields:
            # Combine all text fields
            text_data = df[text_fields].fillna('').apply(lambda x: ' '.join(x), axis=1)
            
            # TF-IDF vectorization
            vectorizer = TfidfVectorizer(max_features=100)
            X_text = vectorizer.fit_transform(text_data).toarray()
            
            # Save vectorizer
            with open(os.path.join(self.models_dir, 'vectorizer.pkl'), 'wb') as f:
                pickle.dump(vectorizer, f)
        
        # Combine all features
        features_list = []
        if X_numeric is not None:
            features_list.append(X_numeric)
        if X_categorical is not None:
            features_list.append(X_categorical)
        if X_text is not None:
            features_list.append(X_text)
            
        if not features_list:
            raise ValueError("No valid features found for preprocessing")
            
        # Combine all feature sets
        if len(features_list) == 1:
            X = features_list[0]
        else:
            X = np.hstack(features_list)
            
        return X, df
    
    def train_anomaly_detector(self, data, numeric_fields, categorical_fields=None, 
                             text_fields=None, contamination=0.05, model_name='iforest'):
        """Train an isolation forest model for anomaly detection"""
        # Preprocess data
        X, _ = self.preprocess_data(
            data, 
            numeric_fields=numeric_fields,
            categorical_fields=categorical_fields,
            text_fields=text_fields
        )
        
        # Train Isolation Forest
        model = IsolationForest(contamination=contamination, random_state=42)
        model.fit(X)
        
        # Save model configuration
        config = {
            'numeric_fields': numeric_fields,
            'categorical_fields': categorical_fields,
            'text_fields': text_fields,
            'contamination': contamination,
            'training_date': datetime.now().isoformat(),
            'model_type': 'isolation_forest'
        }
        
        # Save model and config
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        config_path = os.path.join(self.models_dir, f"{model_name}_config.json")
        
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
            
        with open(config_path, 'w') as f:
            json.dump(config, f)
            
        # Store model in memory
        self.models[model_name] = {
            'model': model,
            'config': config
        }
        
        return {
            'model_name': model_name,
            'model_path': model_path,
            'config_path': config_path
        }
    
    def predict_anomalies(self, data, model_name='iforest', output_file=None):
        """Detect anomalies using a trained model"""
        # Load model if not in memory
        if model_name not in self.models:
            self.load_model(model_name)
            
        model_info = self.models[model_name]
        model = model_info['model']
        config = model_info['config']
        
        # Preprocess data
        X, df = self.preprocess_data(
            data,
            numeric_fields=config['numeric_fields'],
            categorical_fields=config['categorical_fields'],
            text_fields=config['text_fields']
        )
        
        # Predict anomalies (-1 for anomalies, 1 for normal)
        predictions = model.predict(X)
        
        # Calculate anomaly scores
        scores = model.score_samples(X)
        
        # Add predictions to dataframe
        df['anomaly'] = predictions
        df['anomaly_score'] = scores
        
        # Extract anomalies
        anomalies = df[df['anomaly'] == -1]
        
        # Generate result summary
        results = {
            'total_records': len(df),
            'anomaly_count': len(anomalies),
            'anomaly_percentage': (len(anomalies) / len(df)) * 100,
            'model_name': model_name,
            'model_type': config['model_type'],
            'anomalies': anomalies.to_dict('records')
        }
        
        # Save results
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, default=str, indent=2)
        
        return results
    
    def train_classifier(self, data, label_field, feature_fields, 
                       categorical_fields=None, text_fields=None, model_name='rf_classifier'):
        """Train a supervised classifier for known attack patterns"""
        # Preprocess data
        X, df = self.preprocess_data(
            data,
            numeric_fields=feature_fields,
            categorical_fields=categorical_fields,
            text_fields=text_fields
        )
        
        # Get labels
        y = df[label_field].values
        
        # Train Random Forest classifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        
        # Calculate class distribution
        class_distribution = {str(c): int((y == c).sum()) for c in np.unique(y)}
        
        # Get feature importance
        if hasattr(model, 'feature_importances_'):
            feature_importance = model.feature_importances_
        else:
            feature_importance = None
        
        # Save model configuration
        config = {
            'feature_fields': feature_fields,
            'categorical_fields': categorical_fields,
            'text_fields': text_fields,
            'label_field': label_field,
            'training_date': datetime.now().isoformat(),
            'model_type': 'random_forest',
            'class_distribution': class_distribution,
            'classes': [str(c) for c in model.classes_]
        }
        
        # Save model and config
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        config_path = os.path.join(self.models_dir, f"{model_name}_config.json")
        
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
            
        with open(config_path, 'w') as f:
            json.dump(config, f)
            
        # Store model in memory
        self.models[model_name] = {
            'model': model,
            'config': config
        }
        
        return {
            'model_name': model_name,
            'model_path': model_path,
            'config_path': config_path,
            'feature_importance': feature_importance,
            'class_distribution': class_distribution
        }
    
    def predict_classes(self, data, model_name='rf_classifier', output_file=None):
        """Classify data using a trained supervised model"""
        # Load model if not in memory
        if model_name not in self.models:
            self.load_model(model_name)
            
        model_info = self.models[model_name]
        model = model_info['model']
        config = model_info['config']
        
        # Preprocess data
        X, df = self.preprocess_data(
            data,
            numeric_fields=config['feature_fields'],
            categorical_fields=config['categorical_fields'],
            text_fields=config['text_fields']
        )
        
        # Make predictions
        predictions = model.predict(X)
        
        # Get probabilities
        probabilities = model.predict_proba(X)
        
        # Add predictions to dataframe
        df['predicted_class'] = predictions
        
        # Add probability columns
        for i, class_name in enumerate(model.classes_):
            df[f'prob_{class_name}'] = probabilities[:, i]
        
        # Generate result summary
        class_counts = df['predicted_class'].value_counts().to_dict()
        
        results = {
            'total_records': len(df),
            'class_distribution': class_counts,
            'model_name': model_name,
            'model_type': config['model_type'],
            'classified_records': df.to_dict('records')
        }
        
        # Save results
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, default=str, indent=2)
        
        return results
    
    def cluster_events(self, data, numeric_fields, categorical_fields=None, 
                     text_fields=None, eps=0.5, min_samples=5, output_file=None):
        """Cluster events to identify patterns"""
        # Preprocess data
        X, df = self.preprocess_data(
            data,
            numeric_fields=numeric_fields,
            categorical_fields=categorical_fields,
            text_fields=text_fields
        )
        
        # Apply DBSCAN clustering
        dbscan = DBSCAN(eps=eps, min_samples=min_samples)
        clusters = dbscan.fit_predict(X)
        
        # Add cluster assignments to dataframe
        df['cluster'] = clusters
        
        # Calculate cluster statistics
        cluster_stats = {}
        for cluster_id in set(clusters):
            cluster_df = df[df['cluster'] == cluster_id]
            
            # Skip outliers (cluster_id = -1)
            if cluster_id == -1:
                cluster_name = "Outliers"
            else:
                cluster_name = f"Cluster_{cluster_id}"
                
            # Calculate field distributions for this cluster
            field_stats = {}
            for field in numeric_fields:
                if field in df.columns:
                    field_stats[field] = {
                        'mean': float(cluster_df[field].mean()),
                        'std': float(cluster_df[field].std()),
                        'min': float(cluster_df[field].min()),
                        'max': float(cluster_df[field].max())
                    }
            
            # Calculate categorical field distributions
            if categorical_fields:
                for field in categorical_fields:
                    if field in df.columns:
                        value_counts = cluster_df[field].value_counts().to_dict()
                        field_stats[field] = {
                            'value_distribution': value_counts
                        }
            
            cluster_stats[cluster_name] = {
                'size': len(cluster_df),
                'percentage': (len(cluster_df) / len(df)) * 100,
                'field_stats': field_stats
            }
        
        # Generate result summary
        results = {
            'total_records': len(df),
            'num_clusters': len(set(clusters)) - (1 if -1 in clusters else 0),  # Don't count outliers
            'outliers': int((clusters == -1).sum()),
            'cluster_stats': cluster_stats,
            'parameters': {
                'eps': eps,
                'min_samples': min_samples
            }
        }
        
        # Save results
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, default=str, indent=2)
        
        return results
    
    def load_model(self, model_name):
        """Load a saved model from disk"""
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        config_path = os.path.join(self.models_dir, f"{model_name}_config.json")
        
        if not os.path.exists(model_path) or not os.path.exists(config_path):
            raise FileNotFoundError(f"Model {model_name} not found")
            
        # Load model
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
            
        # Load config
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        # Store in memory
        self.models[model_name] = {
            'model': model,
            'config': config
        }
        
        return {
            'model_name': model_name,
            'model_type': config.get('model_type', 'unknown'),
            'training_date': config.get('training_date', 'unknown')
        }
    
    def list_models(self):
        """List all available models"""
        models = []
        
        # Find all config files
        for filename in os.listdir(self.models_dir):
            if filename.endswith('_config.json'):
                model_name = filename.replace('_config.json', '')
                
                # Load config
                config_path = os.path.join(self.models_dir, filename)
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    
                models.append({
                    'name': model_name,
                    'type': config.get('model_type', 'unknown'),
                    'training_date': config.get('training_date', 'unknown')
                })
                
        return models

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='IRF Machine Learning Detection')
    parser.add_argument('--data', required=True, help='Path to data file')
    parser.add_argument('--format', default='tsv', choices=['csv', 'tsv', 'json'], 
                       help='Data file format')
    parser.add_argument('--output', required=True, help='Path to output file')
    parser.add_argument('--action', required=True, 
                      choices=['train-anomaly', 'detect-anomaly', 'train-classifier', 
                               'classify', 'cluster', 'list-models'],
                      help='Action to perform')
    parser.add_argument('--model', default='default_model', help='Model name')
    parser.add_argument('--fields', help='Comma-separated list of fields to use')
    
    args = parser.parse_args()
    
    detector = MLDetector()
    
    if args.action == 'list-models':
        models = detector.list_models()
        print(f"Available models ({len(models)}):")
        for model in models:
            print(f" - {model['name']} ({model['type']}), trained on {model['training_date']}")
        sys.exit(0)
    
    # Load data for all other actions
    data = detector.load_data(args.data, args.format)
    
    if args.action == 'train-anomaly':
        if not args.fields:
            print("Error: --fields is required for training")
            sys.exit(1)
            
        fields = args.fields.split(',')
        result = detector.train_anomaly_detector(data, fields, model_name=args.model)
        print(f"Anomaly detection model trained and saved as: {result['model_path']}")
        
    elif args.action == 'detect-anomaly':
        result = detector.predict_anomalies(data, model_name=args.model, output_file=args.output)
        print(f"Found {result['anomaly_count']} anomalies ({result['anomaly_percentage']:.2f}%)")
        print(f"Results saved to: {args.output}")
        
    elif args.action == 'train-classifier':
        # Additional arguments needed for classification
        parser.add_argument('--label-field', required=True, help='Field containing class labels')
        args = parser.parse_args()
        
        # Validate required fields parameter
        if not args.fields:
            print("Error: --fields is required for training")
            sys.exit(1)
            
        # Parse comma-separated list of feature fields
        fields = args.fields.split(',')
        
        # Train the classifier model using specified fields and label
        result = detector.train_classifier(data, args.label_field, fields, model_name=args.model)
        
        # Output confirmation of successful model training
        print(f"Classification model trained and saved as: {result['model_path']}")
        
    elif args.action == 'classify':
        # Classify data using the specified model and save results to output file
        result = detector.predict_classes(data, model_name=args.model, output_file=args.output)
        
        # Print summary statistics of the classification results
        print(f"Classified {result['total_records']} records")
        print(f"Class distribution: {result['class_distribution']}")
        print(f"Results saved to: {args.output}")
        
    elif args.action == 'cluster':
        # Validate required fields parameter for clustering
        if not args.fields:
            print("Error: --fields is required for clustering")
            sys.exit(1)
            
        # Parse comma-separated list of fields to use for clustering
        fields = args.fields.split(',')
        
        # Perform clustering on the data using the specified fields
        result = detector.cluster_events(data, fields, output_file=args.output)
        
        # Print summary of clustering results
        print(f"Found {result['num_clusters']} clusters and {result['outliers']} outliers")
        print(f"Results saved to: {args.output}")