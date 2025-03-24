#!/usr/bin/env python3
import os

# Directories that need __init__.py files
dirs = [
    'scanners',
    'storage',
    'utils'
]

# Create directories if they don't exist
for d in dirs:
    os.makedirs(d, exist_ok=True)
    init_file = os.path.join(d, '__init__.py')
    if not os.path.exists(init_file):
        with open(init_file, 'w') as f:
            f.write('# Package initialization\n')
        print(f"Created {init_file}")

# Create required directories for logs and reports
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)

print("All __init__.py files and required directories have been created!")