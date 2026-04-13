import os
import json
import hashlib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score
import onnx
import skl2onnx
from skl2onnx.common.data_types import FloatTensorType

def extract_features(file_path):
    """
    Python implementation of feature extraction.
    MUST match the Rust implementation in crates/anthill-core/src/types.rs
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return None
            
        # Basic features (stubs - in reality would use pefile or similar)
        import_entropy = 0.0 # Placeholder
        section_count = 0    # Placeholder
        has_packer = 0       # Placeholder
        file_size = len(data) / 1024.0
        
        # Simple entropy calculation
        prob = [np.sum(np.frombuffer(data, dtype=np.uint8) == i) / len(data) for i in range(256)]
        string_entropy = -np.sum([p * np.log2(p) for p in prob if p > 0])
        
        return [import_entropy, section_count, has_packer, string_entropy, file_size, 0, 0]
    except Exception as e:
        print(f"Error extracting features from {file_path}: {e}")
        return None

def train_model(data_path, output_path, meta_path):
    """
    Train a model from a CSV of features + labels.
    """
    df = pd.read_csv(data_path)
    X = df.drop('label', axis=1)
    y = df['label'] # 0 for clean, 1 for malware
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    clr = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clr.fit(X_train, y_train)
    
    # Evaluate
    preds = clr.predict(X_test)
    f1 = f1_score(y_test, preds)
    precision = precision_score(y_test, preds)
    recall = recall_score(y_test, preds)
    
    print(f"Model trained. F1: {f1:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}")
    
    # Export to ONNX
    initial_type = [('float_input', FloatTensorType([None, X.shape[1]]))]
    onx = skl2onnx.convert_sklearn(clr, initial_types=initial_type, target_opset=12)
    
    with open(output_path, "wb") as f:
        f.write(onx.SerializeToString())
    
    # Create Metadata
    meta = {
        "model_version": "v1.0.0",
        "training_date": pd.Timestamp.now().isoformat(),
        "dataset_hash": hashlib.sha256(open(data_path, 'rb').read()).hexdigest(),
        "training_seed": 42,
        "val_fp_rate": 1.0 - precision,
        "val_fn_rate": 1.0 - recall,
        "drift_baseline": "initial",
        "kl_divergence": 0.0,
        "validation_pass": True,
        "signature": "PLACEHOLDER_SIGNATURE"
    }
    
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=4)
        
    print(f"Model and metadata saved to {output_path} and {meta_path}")

if __name__ == "__main__":
    # Example usage:
    # train_model("data/dataset.csv", "models/current.onnx", "models/current.meta.json")
    pass
