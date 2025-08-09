#!/usr/bin/env python3
"""
Script to copy test cases to Spotter rule test files.
"""

import os
import json
import yaml
import glob
from pathlib import Path
from typing import Dict, List, Tuple, Optional

def load_yaml(file_path: str) -> dict:
    """Load a YAML file and return its content. Handle multi-document YAML files."""
    try:
        with open(file_path, 'r') as f:
            # Try to load as a single document first
            documents = list(yaml.safe_load_all(f))
            if len(documents) == 1:
                return documents[0]
            elif len(documents) > 1:
                # For multi-document YAML, return the first non-empty document
                for doc in documents:
                    if doc:
                        return doc
                return {}
            else:
                return {}
    except Exception as e:
        print(f"Error loading YAML from {file_path}: {e}")
        return {}

def save_yaml(data: List[dict], file_path: str):
    """Save data to a YAML file with proper formatting."""
    try:
        with open(file_path, 'w') as f:
            # Custom format for better readability
            for i, test_case in enumerate(data):
                if i > 0:
                    f.write('\n')
                f.write(f"- name: {test_case['name']}\n")
                f.write(f"  pass: {str(test_case['pass']).lower()}\n")
                f.write(f"  input: |\n")
                # Indent each line of the input YAML by 4 spaces
                for line in test_case['input'].split('\n'):
                    f.write(f"    {line}\n")
        print(f"Saved test file: {file_path}")
    except Exception as e:
        print(f"Error saving YAML to {file_path}: {e}")

def load_json(file_path: str) -> dict:
    """Load a JSON file and return its content."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON from {file_path}: {e}")
        return {}

def find_kics_rule_directory(rule_name: str, kics_base_path: str) -> Optional[str]:
    """Find the corresponding KICS rule directory by matching rule name."""
    kics_queries_path = os.path.join(kics_base_path, "assets", "queries", "k8s")
    
    if not os.path.exists(kics_queries_path):
        print(f"KICS queries path not found: {kics_queries_path}")
        return None
    
    # List all directories in the KICS queries path
    for dir_name in os.listdir(kics_queries_path):
        dir_path = os.path.join(kics_queries_path, dir_name)
        if os.path.isdir(dir_path):
            metadata_path = os.path.join(dir_path, "metadata.json")
            if os.path.exists(metadata_path):
                metadata = load_json(metadata_path)
                if metadata.get("queryName") == rule_name:
                    print(f"Found matching KICS rule: {dir_name} for '{rule_name}'")
                    return dir_path
    
    print(f"No matching KICS rule found for: {rule_name}")
    return None

def get_raw_yaml_content(file_path: str) -> str:
    """Get raw YAML content from file, preserving multi-document files as-is."""
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            return content
    except Exception as e:
        print(f"Error reading raw YAML from {file_path}: {e}")
        return ""

def get_kics_test_cases(kics_rule_dir: str) -> Tuple[List[str], List[str]]:
    """Extract test cases from KICS rule directory."""
    test_dir = os.path.join(kics_rule_dir, "test")
    negative_tests = []
    positive_tests = []
    
    if not os.path.exists(test_dir):
        print(f"No test directory found in {kics_rule_dir}")
        return negative_tests, positive_tests
    
    # Process all test files
    for file_name in os.listdir(test_dir):
        if file_name.endswith('.yaml') or file_name.endswith('.yml'):
            file_path = os.path.join(test_dir, file_name)
            
            # Get raw YAML content
            raw_content = get_raw_yaml_content(file_path)
            
            if not raw_content:
                continue
                
            # Determine if it's negative or positive based on filename
            if 'negative' in file_name.lower():
                negative_tests.append(raw_content)
                print(f"Found negative test: {file_name}")
            elif 'positive' in file_name.lower():
                positive_tests.append(raw_content)
                print(f"Found positive test: {file_name}")
    
    return negative_tests, positive_tests

def create_test_case(test_content: str, test_type: str, test_num: int) -> dict:
    """Create a test case in the format expected by Spotter."""
    # KICS semantics: positive = should trigger (insecure), negative = should not trigger (secure)
    # Spotter semantics: pass=false = should trigger (insecure), pass=true = should not trigger (secure)
    if test_type == "positive":  # KICS positive = should trigger = insecure
        name = f"insecure sample {test_num} should fail"
        pass_value = False
    else:  # KICS negative = should not trigger = secure
        name = f"secure sample {test_num} should pass"
        pass_value = True
    
    # Add namespace if missing, but preserve original formatting
    lines = test_content.split('\n')
    input_yaml = test_content
    
    # Check if namespace exists
    try:
        parsed_content = yaml.safe_load(test_content)
        if parsed_content and isinstance(parsed_content, dict):
            if 'metadata' not in parsed_content or 'namespace' not in parsed_content.get('metadata', {}):
                # Find where to insert namespace in the raw YAML
                for i, line in enumerate(lines):
                    if line.strip().startswith('metadata:'):
                        # Found metadata section, add namespace after it
                        indent = '  '  # Use 2-space indent
                        if i + 1 < len(lines) and lines[i + 1].strip():
                            # There's content after metadata, insert namespace as first item
                            lines.insert(i + 1, f"{indent}namespace: kube-system")
                        else:
                            # Empty metadata, just add namespace
                            lines.insert(i + 1, f"{indent}namespace: kube-system")
                        input_yaml = '\n'.join(lines)
                        break
                else:
                    # No metadata section found, add it
                    for i, line in enumerate(lines):
                        if line.strip().startswith('kind:') or line.strip().startswith('apiVersion:'):
                            # Insert after kind/apiVersion
                            continue
                        else:
                            lines.insert(i, 'metadata:')
                            lines.insert(i + 1, '  namespace: kube-system')
                            input_yaml = '\n'.join(lines)
                            break
    except:
        # If parsing fails, use raw content
        pass
    
    return {
        "name": name,
        "pass": pass_value,
        "input": input_yaml
    }

def process_rule_file(rule_file_path: str, kics_base_path: str, dry_run: bool = True):
    """Process a single rule file and copy test cases from KICS."""
    print(f"\n--- Processing rule file: {rule_file_path} ---")
    
    # Load the rule file
    rule_data = load_yaml(rule_file_path)
    if not rule_data:
        print(f"Failed to load rule data from {rule_file_path}")
        return
    
    # Extract rule name from spec.name
    rule_name = rule_data.get("spec", {}).get("name")
    if not rule_name:
        print(f"No spec.name found in {rule_file_path}")
        return
    
    print(f"Rule name: {rule_name}")
    
    # Find corresponding KICS rule directory
    kics_rule_dir = find_kics_rule_directory(rule_name, kics_base_path)
    if not kics_rule_dir:
        return
    
    # Get KICS test cases
    negative_tests, positive_tests = get_kics_test_cases(kics_rule_dir)
    
    if not negative_tests and not positive_tests:
        print(f"No test cases found in KICS for {rule_name}")
        return
    
    # Determine test file path
    rule_dir = os.path.dirname(rule_file_path)
    rule_basename = os.path.basename(rule_file_path).replace('.yaml', '').replace('.yml', '')
    test_file_path = os.path.join(rule_dir, f"{rule_basename}-test.yaml")
    
    # Load existing test cases if file exists
    existing_tests = []
    if os.path.exists(test_file_path):
        existing_tests = load_yaml(test_file_path) or []
        if not isinstance(existing_tests, list):
            existing_tests = []
        print(f"Found {len(existing_tests)} existing test cases")
    
    # Create new test cases
    new_tests = existing_tests.copy()
    
    # Add positive test cases (KICS positive = insecure = should fail)
    for i, positive_test in enumerate(positive_tests, 1):
        test_case = create_test_case(positive_test, "positive", i)
        new_tests.append(test_case)
        print(f"Added insecure test case: {test_case['name']}")
    
    # Add negative test cases (KICS negative = secure = should pass)
    for i, negative_test in enumerate(negative_tests, 1):
        test_case = create_test_case(negative_test, "negative", i)
        new_tests.append(test_case)
        print(f"Added secure test case: {test_case['name']}")
    
    print(f"Total test cases: {len(new_tests)} (was {len(existing_tests)})")
    
    if dry_run:
        print(f"DRY RUN: Would save {len(new_tests)} test cases to {test_file_path}")
        print("Sample test cases:")
        for i, test in enumerate(new_tests[-min(2, len(new_tests)):], 1):
            print(f"  {i}. {test['name']} (pass: {test['pass']})")
    else:
        # Save the updated test file
        save_yaml(new_tests, test_file_path)

def main():
    """Main function to process rule files."""
    import argparse

    parser = argparse.ArgumentParser(description="Copy KICS test cases to Spotter rule test files")
    parser.add_argument("--rules-path", required=True, help="Path to the directory containing Spotter rule YAMLs")
    parser.add_argument("--kics-path", default=None, help="Path to the KICS repository root (default: <workspace>/kics)")
    parser.add_argument("--workspace", default=None, help="Workspace root (default: auto-detect from script location)")
    parser.add_argument("--dry-run", action="store_true", help="Do not write files, only print actions")

    args = parser.parse_args()

    # Resolve workspace path
    if args.workspace:
        workspace_path = args.workspace
    else:
        # Assume script is placed in workspace root
        workspace_path = str(Path(__file__).resolve().parent)

    # Resolve KICS path
    if args.kics_path:
        kics_base_path = args.kics_path
    else:
        kics_base_path = os.path.join(workspace_path, "kics")

    # Resolve rules path
    rules_base_path = args.rules_path

    print("=== KICS Test Case Copy Script ===")
    print(f"Workspace: {workspace_path}")
    print(f"KICS path: {kics_base_path}")
    print(f"Rules path: {rules_base_path}")

    if not os.path.isdir(rules_base_path):
        print(f"Rules path does not exist or is not a directory: {rules_base_path}")
        return

    # Find all rule files in the directory
    try:
        dir_entries = os.listdir(rules_base_path)
    except Exception as e:
        print(f"Failed to list rules path {rules_base_path}: {e}")
        return

    rule_files = []
    for file_name in dir_entries:
        if file_name.endswith('.yaml') and not file_name.endswith('-test.yaml') and not file_name.endswith('-test.yml'):
            rule_files.append(file_name)

    print(f"Found {len(rule_files)} rule files to process...")

    # Process each rule file
    for rule_file in sorted(rule_files):
        rule_file_path = os.path.join(rules_base_path, rule_file)
        if os.path.exists(rule_file_path):
            process_rule_file(rule_file_path, kics_base_path, dry_run=args.dry_run)
        else:
            print(f"Rule file not found: {rule_file_path}")

    print("\n=== Script completed ===")
    print("IMPORTANT: Some rules may have namespace restrictions that require manual review.")
    print("If tests fail with 'rule criteria didn't match resource', check namespace settings.")
    print("Validate generated files with: go run . rules validate <rules-path> --test-cases")

if __name__ == "__main__":
    main()
