#!/usr/bin/env python3
"""
Visualization module for the Incident Response Framework
Handles creating visual representations of security data and incidents
"""

import os
import sys
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import traceback

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

class SecurityVisualizer:
    def __init__(self, output_dir=None):
        """Initialize the visualizer with an output directory"""
        self.output_dir = output_dir or os.path.join(
            os.environ.get('IRF_EVIDENCE_DIR', '.'), 'visualizations')
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
        # Set default styling for visualizations
        sns.set_style("darkgrid")
        plt.rcParams['figure.figsize'] = (12, 8)
        
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
            
    def event_timeline(self, data, timestamp_field='timestamp', category_field=None, 
                      title="Security Event Timeline", filename=None):
        """Create timeline visualization of security events"""
        # Convert timestamp to datetime if needed
        df = data.copy()
        if df[timestamp_field].dtype != 'datetime64[ns]':
            df[timestamp_field] = pd.to_datetime(df[timestamp_field])
        
        # Sort by timestamp
        df = df.sort_values(timestamp_field)
        
        fig, ax = plt.subplots()
        
        # Create basic timeline
        if category_field:
            # Colored timeline by category
            categories = df[category_field].unique()
            colors = plt.cm.tab10(np.linspace(0, 1, len(categories)))
            
            for i, category in enumerate(categories):
                cat_data = df[df[category_field] == category]
                ax.scatter(cat_data[timestamp_field], [i] * len(cat_data), 
                           label=category, color=colors[i], s=100)
                
            ax.set_yticks(range(len(categories)))
            ax.set_yticklabels(categories)
        else:
            # Single timeline
            ax.scatter(df[timestamp_field], [0] * len(df), s=100, color='blue')
            ax.set_yticks([])
            
        # Format x-axis for timestamps
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
        plt.xticks(rotation=45)
        
        plt.title(title)
        plt.tight_layout()
        
        # Save or show
        if filename:
            output_path = os.path.join(self.output_dir, filename)
            plt.savefig(output_path)
            plt.close()
            return output_path
        else:
            plt.show()
            return None
    
    def alert_heatmap(self, data, timestamp_field='timestamp', rule_field='RULE_ID', 
                     title="Alert Frequency Heatmap", filename=None):
        """Create heatmap showing alert frequencies by time and rule"""
        # Prepare data
        df = data.copy()
        if df[timestamp_field].dtype != 'datetime64[ns]':
            df[timestamp_field] = pd.to_datetime(df[timestamp_field])
            
        # Extract hour and day
        df['hour'] = df[timestamp_field].dt.hour
        df['day'] = df[timestamp_field].dt.day_name()
        
        # Create pivot table for heatmap
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        pivot = pd.pivot_table(df, values=rule_field, index='day', columns='hour', 
                              aggfunc='count', fill_value=0)
        
        # Reorder days
        if all(day in pivot.index for day in day_order):
            pivot = pivot.reindex(day_order)
        
        # Create heatmap
        plt.figure(figsize=(14, 8))
        ax = sns.heatmap(pivot, cmap='YlOrRd', annot=True, fmt='g')
        
        plt.title(title)
        plt.xlabel('Hour of Day')
        plt.ylabel('Day of Week')
        
        # Save or show
        if filename:
            output_path = os.path.join(self.output_dir, filename)
            plt.savefig(output_path)
            plt.close()
            return output_path
        else:
            plt.show()
            return None
    
    def rule_distribution(self, data, rule_field='RULE_ID', severity_field='SEVERITY',
                         title="Detection Rule Distribution", filename=None):
        """Create bar chart showing distribution of triggered rules"""
        # Count rules
        rule_counts = data[rule_field].value_counts().reset_index()
        rule_counts.columns = ['rule', 'count']
        
        # Sort by count
        rule_counts = rule_counts.sort_values('count', ascending=False)
        
        # Limit to top 20 rules for readability
        if len(rule_counts) > 20:
            rule_counts = rule_counts.head(20)
            
        # Create bar chart
        plt.figure(figsize=(15, 8))
        
        # Color by severity if available
        if severity_field in data.columns:
            # Get most common severity for each rule
            severity_map = {}
            for rule in rule_counts['rule']:
                rule_data = data[data[rule_field] == rule]
                severity_map[rule] = rule_data[severity_field].value_counts().idxmax()
                
            # Define colors for severities
            severity_colors = {
                'CRITICAL': 'darkred',
                'HIGH': 'red',
                'MEDIUM': 'orange',
                'LOW': 'yellow',
                'INFO': 'green'
            }
            
            # Create bars with colors
            bars = plt.bar(rule_counts['rule'], rule_counts['count'], 
                          color=[severity_colors.get(severity_map.get(rule, 'MEDIUM'), 'gray') 
                                for rule in rule_counts['rule']])
                                
            # Add legend
            from matplotlib.patches import Patch
            legend_elements = [Patch(facecolor=color, label=sev) 
                              for sev, color in severity_colors.items() 
                              if sev in severity_map.values()]
            plt.legend(handles=legend_elements)
        else:
            # Simple bar chart without severity coloring
            bars = plt.bar(rule_counts['rule'], rule_counts['count'])
        
        plt.title(title)
        plt.xlabel('Detection Rule')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save or show
        if filename:
            output_path = os.path.join(self.output_dir, filename)
            plt.savefig(output_path)
            plt.close()
            return output_path
        else:
            plt.show()
            return None
    
    def network_graph(self, data, source_field='source_ip', target_field='target_ip',
                     title="Network Communication Graph", filename=None):
        """Create network graph visualization of communications"""
        try:
            import networkx as nx
        except ImportError:
            print("NetworkX library required for network graphs. Install with: pip install networkx")
            return None
            
        # Create graph
        G = nx.Graph()
        
        # Add nodes and edges
        for _, row in data.iterrows():
            source = row[source_field]
            target = row[target_field]
            
            if not G.has_node(source):
                G.add_node(source)
            if not G.has_node(target):
                G.add_node(target)
                
            # Add edge or increment weight if exists
            if G.has_edge(source, target):
                G[source][target]['weight'] += 1
            else:
                G.add_edge(source, target, weight=1)
        
        # Create visualization
        plt.figure(figsize=(15, 15))
        
        # Calculate node size based on degree
        node_size = [G.degree(node) * 100 for node in G.nodes()]
        
        # Calculate edge width based on weight
        edge_width = [G[u][v]['weight'] / 2 for u, v in G.edges()]
        
        # Spring layout
        pos = nx.spring_layout(G, seed=42)
        
        # Draw nodes and edges
        nx.draw_networkx_nodes(G, pos, node_size=node_size, node_color='lightblue')
        nx.draw_networkx_edges(G, pos, width=edge_width, alpha=0.7)
        nx.draw_networkx_labels(G, pos, font_size=8)
        
        plt.title(title)
        plt.axis('off')
        
        # Save or show
        if filename:
            output_path = os.path.join(self.output_dir, filename)
            plt.savefig(output_path)
            plt.close()
            return output_path
        else:
            plt.show()
            return None
    
    def create_dashboard(self, data_files, output_file='security_dashboard.html'):
        """Create an HTML dashboard with multiple visualizations"""
        try:
            from jinja2 import Template
        except ImportError:
            print("Jinja2 library required for dashboards. Install with: pip install jinja2")
            return None
            
        # Generate all visualizations
        visualization_paths = []
        
        # Process each data file
        for data_file in data_files:
            data = self.load_data(data_file['path'], data_file.get('format', 'tsv'))
            
            # Generate visualizations based on data type
            if 'alert' in data_file['type'].lower():
                # Alert data
                timeline = self.event_timeline(
                    data, category_field='SEVERITY',
                    filename=f"timeline_{os.path.basename(data_file['path'])}.png"
                )
                heatmap = self.alert_heatmap(
                    data, 
                    filename=f"heatmap_{os.path.basename(data_file['path'])}.png"
                )
                dist = self.rule_distribution(
                    data,
                    filename=f"distribution_{os.path.basename(data_file['path'])}.png"
                )
                
                visualization_paths.extend([
                    {'title': 'Alert Timeline', 'path': timeline, 'type': 'image'},
                    {'title': 'Alert Heatmap', 'path': heatmap, 'type': 'image'},
                    {'title': 'Rule Distribution', 'path': dist, 'type': 'image'}
                ])
                
            elif 'network' in data_file['type'].lower():
                # Network data
                graph = self.network_graph(
                    data,
                    filename=f"network_{os.path.basename(data_file['path'])}.png"
                )
                
                visualization_paths.append(
                    {'title': 'Network Communication Graph', 'path': graph, 'type': 'image'}
                )
        
        # Create HTML dashboard using template
        dashboard_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .dashboard { display: flex; flex-wrap: wrap; }
                .visualization { margin: 15px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .visualization img { max-width: 100%; }
                .visualization h2 { padding: 10px; background: #f0f0f0; margin: 0; }
                .visualization-content { padding: 15px; }
            </style>
        </head>
        <body>
            <h1>Security Dashboard</h1>
            <p>Generated on: {{ timestamp }}</p>
            
            <div class="dashboard">
                {% for viz in visualizations %}
                <div class="visualization">
                    <h2>{{ viz.title }}</h2>
                    <div class="visualization-content">
                        {% if viz.type == 'image' %}
                        <img src="{{ viz.path }}" alt="{{ viz.title }}">
                        {% else %}
                        <pre>{{ viz.content }}</pre>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
        </body>
        </html>
        """
        
        # Render template
        template = Template(dashboard_template)
        html_content = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            visualizations=visualization_paths
        )
        
        # Write dashboard to file
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w') as f:
            f.write(html_content)
            
        return output_path

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='IRF Security Data Visualizer')
    parser.add_argument('--data', required=True, help='Path to data file')
    parser.add_argument('--format', default='tsv', choices=['csv', 'tsv', 'json'], 
                      help='Data file format')
    parser.add_argument('--output', required=True, help='Output directory for visualizations')
    parser.add_argument('--type', default='timeline', 
                      choices=['timeline', 'heatmap', 'distribution', 'network', 'dashboard'], 
                      help='Visualization type to generate')
    
    args = parser.parse_args()
    
    @handle_errors
    def main():
        visualizer = SecurityVisualizer(args.output)
        data = visualizer.load_data(args.data, args.format)
        
        if args.type == 'timeline':
            # Generate a timeline visualization of security events
            visualizer.event_timeline(data, filename='event_timeline.png')
        elif args.type == 'heatmap':
            # Create a heatmap showing the frequency of alerts by time and rule
            visualizer.alert_heatmap(data, filename='alert_heatmap.png')
        elif args.type == 'distribution':
            # Generate a bar chart showing the distribution of security rules that triggered alerts
            visualizer.rule_distribution(data, filename='rule_distribution.png')
        elif args.type == 'network':
            # Create a network graph visualization showing communication patterns between IP addresses
            visualizer.network_graph(data, filename='network_graph.png')
        elif args.type == 'dashboard':
            # Generate a comprehensive HTML dashboard containing multiple visualizations of the security data
            # This combines several visualization types into a single interactive report
            visualizer.create_dashboard([{'path': args.data, 'format': args.format, 'type': 'alert'}])
            
        # Inform the user where the generated visualization files have been saved
        print(f"Visualization(s) generated in: {args.output}")
    
    main()