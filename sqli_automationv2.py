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
from multiprocessing import Pool, cpu_count

class SQLITester:
    def __init__(self, target_url, cookie_name="pid"):
        self.target_url = target_url
        self.cookie_name = cookie_name
        self.session = self._setup_session()
        
    def _setup_session(self):
        session = requests.Session()
        retries = Retry(
            total=5,  # Mengurangi jumlah retry
            backoff_factor=0.1,  # Mengurangi waktu tunggu
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session

    def test_payload(self, payload):
        sqlmap_cmd = [
            'sqlmap',
            '-u', self.target_url,
            '--cookie', f"{self.cookie_name}={payload}",
            '--batch',
            '--random-agent',
            '--level', '3',  # Menurunkan level
            '--risk', '2',   # Menurunkan risk
            '--threads', '10',  # Meningkatkan threads
            '--timeout', '30',  # Menambah timeout
            '--output-dir', '/tmp/sqlmap_results',
            '--fresh-queries',
            '--smart',        # Menggunakan mode smart
            '--null-connection',  # Menggunakan null connection
            '--technique=BEUSTQ'  # Specify teknik yang digunakan
        ]
        
        try:
            process = subprocess.run(
                sqlmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60  # Mengurangi timeout
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

    def process_test_batch(self, args):
        features, dataset, test_num, total_tests = args
        print(f"\n[*] Running test {test_num + 1}/{total_tests}")
        blocked_count = self._run_single_test(features.copy(), dataset.copy())
        print(f"[+] Test {test_num + 1} complete: {blocked_count} payloads blocked")
        return blocked_count

    def run_test_campaign(self, features_file, dataset_file, output_file, num_tests=100):
        try:
            features = np.load(features_file)
            dataset = np.load(dataset_file)
        except Exception as e:
            print(f"Error loading files: {str(e)}")
            return []

        os.makedirs('/tmp/sqlmap_results', exist_ok=True)

        # Persiapkan argumen untuk multiprocessing
        test_args = [(features, dataset, i, num_tests) for i in range(num_tests)]
        
        # Gunakan multiprocessing
        num_processes = min(cpu_count(), 4)  # Batasi maksimal 4 proses
        print(f"Running tests with {num_processes} parallel processes...")
        
        with Pool(processes=num_processes) as pool:
            results = []
            for result in pool.imap_unordered(self.process_test_batch, test_args):
                results.append(result)
                np.save(output_file, np.array(results))
                print(f"Progress: {len(results)}/{num_tests} tests completed")

        return results

    def _run_single_test(self, features, dataset, k=5):  # Mengurangi jumlah kandidat
        blocked = []
        current_features = features.copy()
        current_dataset = dataset.copy()
        max_attempts = 10  # Batasi jumlah percobaan
        
        for _ in range(max_attempts):
            candidates = self._select_candidates(current_dataset, current_features, k)
            test_payload = self._select_best_payload(candidates, blocked)
            
            if self.test_payload(test_payload['payload']):
                return len(blocked)
            
            blocked.append(test_payload['features'])
            
        return len(blocked)

    def _select_candidates(self, dataset, features, k):
        indices = np.random.choice(min(len(dataset), k*2), k, replace=False)
        return [{'payload': dataset[i], 'features': features[i]} for i in indices]

    def _select_best_payload(self, candidates, blocked):
        if not blocked:
            return candidates[0]  # Ambil kandidat pertama untuk kecepatan
            
        max_distance = -1
        best_candidate = candidates[0]
        
        for candidate in candidates:
            if not blocked:
                min_dist = float('inf')
            else:
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
    parser.add_argument('--processes', type=int, default=None, help='Number of parallel processes')
    
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

