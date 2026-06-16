import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier

# Import features description
try:
    from features import FEATURE_KEYS
except ImportError:
    # Fallback to local import structure if run as module
    from ml.features import FEATURE_KEYS

# Create model directories
os.makedirs("ml/models", exist_ok=True)
os.makedirs("backend/app/models", exist_ok=True)

def generate_synthetic_data(num_samples=10000):
    """Generates a realistic synthetic dataset based on feature distributions of benign/phishing sites."""
    np.random.seed(42)
    data = []
    
    # 0 = Benign (Safe), 1 = Phishing
    labels = np.random.choice([0, 1], size=num_samples, p=[0.6, 0.4])
    
    for label in labels:
        row = {}
        if label == 0:  # Benign
            row["url_length"] = int(np.random.normal(35, 10))
            row["domain_length"] = int(np.random.normal(15, 4))
            row["qty_dots"] = int(np.random.choice([1, 2, 3], p=[0.7, 0.2, 0.1]))
            row["qty_hyphens"] = int(np.random.choice([0, 1, 2], p=[0.8, 0.15, 0.05]))
            row["qty_underline"] = 0
            row["qty_slash"] = int(np.random.choice([2, 3, 4], p=[0.4, 0.4, 0.2]))
            row["qty_question"] = int(np.random.choice([0, 1], p=[0.95, 0.05]))
            row["qty_equal"] = int(np.random.choice([0, 1, 2], p=[0.9, 0.08, 0.02]))
            row["qty_at"] = 0
            row["qty_and"] = 0
            row["qty_exclamation"] = 0
            row["qty_tilde"] = 0
            row["qty_comma"] = 0
            row["qty_plus"] = 0
            row["qty_asterisk"] = 0
            row["qty_hashtag"] = 0
            row["qty_dollar"] = 0
            row["qty_percent"] = 0
            row["qty_subdomains"] = int(np.random.choice([0, 1], p=[0.9, 0.1]))
            row["has_ip"] = 0
            row["is_shortened"] = int(np.random.choice([0, 1], p=[0.98, 0.02]))
            row["has_login_keyword"] = int(np.random.choice([0, 1], p=[0.96, 0.04]))
            row["is_https"] = int(np.random.choice([0, 1], p=[0.05, 0.95]))  # Benign mostly HTTPS
            row["external_links_ratio"] = float(np.random.uniform(0.0, 0.3))
            row["iframe_present"] = int(np.random.choice([0, 1], p=[0.99, 0.01]))
            row["disables_right_click"] = 0
            row["has_unsafe_form"] = int(np.random.choice([0, 1], p=[0.98, 0.02]))
            row["favicon_external"] = int(np.random.choice([0, 1], p=[0.9, 0.1]))
        else:  # Phishing
            row["url_length"] = int(np.random.normal(85, 25))
            row["domain_length"] = int(np.random.normal(25, 8))
            row["qty_dots"] = int(np.random.choice([2, 3, 4, 5], p=[0.2, 0.4, 0.3, 0.1]))
            row["qty_hyphens"] = int(np.random.choice([0, 1, 2, 3, 4], p=[0.3, 0.3, 0.2, 0.1, 0.1]))
            row["qty_underline"] = int(np.random.choice([0, 1], p=[0.8, 0.2]))
            row["qty_slash"] = int(np.random.choice([3, 4, 5, 6], p=[0.1, 0.3, 0.4, 0.2]))
            row["qty_question"] = int(np.random.choice([0, 1], p=[0.7, 0.3]))
            row["qty_equal"] = int(np.random.choice([0, 1, 2, 3], p=[0.6, 0.2, 0.1, 0.1]))
            row["qty_at"] = int(np.random.choice([0, 1], p=[0.9, 0.1]))
            row["qty_and"] = int(np.random.choice([0, 1], p=[0.8, 0.2]))
            row["qty_exclamation"] = int(np.random.choice([0, 1], p=[0.95, 0.05]))
            row["qty_tilde"] = 0
            row["qty_comma"] = 0
            row["qty_plus"] = 0
            row["qty_asterisk"] = 0
            row["qty_hashtag"] = 0
            row["qty_dollar"] = 0
            row["qty_percent"] = int(np.random.choice([0, 1], p=[0.9, 0.1]))
            row["qty_subdomains"] = int(np.random.choice([0, 1, 2, 3], p=[0.2, 0.4, 0.3, 0.1]))
            row["has_ip"] = int(np.random.choice([0, 1], p=[0.92, 0.08]))
            row["is_shortened"] = int(np.random.choice([0, 1], p=[0.85, 0.15]))
            row["has_login_keyword"] = int(np.random.choice([0, 1], p=[0.4, 0.6]))
            row["is_https"] = int(np.random.choice([0, 1], p=[0.6, 0.4]))  # Phishing often lacks HTTPS
            row["external_links_ratio"] = float(np.random.uniform(0.4, 0.9))
            row["iframe_present"] = int(np.random.choice([0, 1], p=[0.8, 0.2]))
            row["disables_right_click"] = int(np.random.choice([0, 1], p=[0.9, 0.1]))
            row["has_unsafe_form"] = int(np.random.choice([0, 1], p=[0.3, 0.7]))
            row["favicon_external"] = int(np.random.choice([0, 1], p=[0.5, 0.5]))
            
        row["label"] = label
        data.append(row)
        
    df = pd.DataFrame(data)
    # Ensure non-negative bounds
    for col in df.columns:
        if col != "external_links_ratio" and col != "label":
            df[col] = df[col].clip(lower=0)
    return df

def train():
    print("Loading / generating dataset...")
    df = generate_synthetic_data(10000)
    
    X = df[FEATURE_KEYS]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training machine learning model...")
    # Attempt to import XGBoost
    xgb_available = False
    try:
        import xgboost as xgb
        print("XGBoost is available. Training XGBoost model...")
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            eval_metric="logloss"
        )
        xgb_available = True
    except ImportError:
        print("XGBoost not installed. Training RandomForestClassifier as fallback...")
        model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
        
    model.fit(X_train, y_train)
    
    # Predict
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n--- MODEL PERFORMANCE ---")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {auc:.4f}")
    print("Confusion Matrix:\n", cm)
    
    # Extract feature importance
    if xgb_available:
        importances = model.feature_importances_.tolist()
    else:
        importances = model.feature_importances_.tolist()
        
    feature_importance_dict = dict(zip(FEATURE_KEYS, importances))
    # Sort importances
    sorted_importance = sorted(feature_importance_dict.items(), key=lambda x: x[1], reverse=True)
    print("\nTop 5 Features:")
    for f, imp in sorted_importance[:5]:
        print(f" - {f}: {imp:.4f}")
        
    # Save model artifacts
    model_data = {
        "model_type": "xgboost" if xgb_available else "random_forest",
        "feature_keys": FEATURE_KEYS,
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "roc_auc": float(auc),
            "confusion_matrix": cm.tolist()
        },
        "feature_importance": feature_importance_dict
    }
    
    # Save training report json
    with open("ml/models/training_report.json", "w") as f:
        json.dump(model_data, f, indent=4)
    with open("backend/app/models/training_report.json", "w") as f:
        json.dump(model_data, f, indent=4)
        
    # Save the actual model
    if xgb_available:
        model.save_model("ml/models/phishguard_model.json")
        model.save_model("backend/app/models/phishguard_model.json")
    else:
        with open("ml/models/phishguard_model.pkl", "wb") as f:
            pickle.dump(model, f)
        with open("backend/app/models/phishguard_model.pkl", "wb") as f:
            pickle.dump(model, f)
            
    print("\nModel saved successfully in ml/models/ and backend/app/models/")

if __name__ == "__main__":
    train()
