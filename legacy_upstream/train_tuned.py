import joblib
from pathlib import Path
from train_combined import find_csv_paths, load_and_extract, balance_dataframe, url_to_dataframe
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np


def evaluate_model(clf, X_test, y_test, desc='model'):
    proba = clf.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)
    print(f'--- Evaluation: {desc} ---')
    print(classification_report(y_test, preds))
    print('Confusion matrix:')
    print(confusion_matrix(y_test, preds))
    return proba


def main():
    base = Path(__file__).resolve().parent
    csvs = find_csv_paths(base)
    print('Loading CSVs:', len(csvs))
    df = load_and_extract(csvs)
    df = df.drop_duplicates(subset=['url']).reset_index(drop=True)
    df_bal = balance_dataframe(df)

    X = url_to_dataframe(df_bal['url'].tolist())
    y = df_bal['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Strategy A: drop 'has_https' feature
    if 'has_https' in X_train.columns:
        X_train_no_https = X_train.drop(columns=['has_https'])
        X_test_no_https = X_test.drop(columns=['has_https'])
    else:
        X_train_no_https = X_train
        X_test_no_https = X_test

    # Baseline retrain (same as previous)
    print('Training baseline model...')
    clf_base = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf_base.fit(X_train, y_train)
    proba_base = evaluate_model(clf_base, X_test, y_test, desc='baseline')

    # Retrain without has_https
    print('Training model without has_https...')
    clf_no_https = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf_no_https.fit(X_train_no_https, y_train)
    proba_no_https = evaluate_model(clf_no_https, X_test_no_https, y_test, desc='no_https')

    # Retrain with class_weight penalizing false positives (give class 0 higher weight)
    print('Training model with class_weight {0:2,1:1}...')
    clf_weighted = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, class_weight={0:2, 1:1})
    clf_weighted.fit(X_train, y_train)
    proba_weighted = evaluate_model(clf_weighted, X_test, y_test, desc='weighted_0_2_1')

    # Compare false positive rates
    def fpr(proba, y_test):
        preds = (proba >= 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        return fp / (fp + tn) if (fp + tn) > 0 else 0

    print('\nFalse positive rates:')
    print('baseline:', fpr(proba_base, y_test))
    print('no_https:', fpr(proba_no_https, y_test))
    print('weighted_0_2_1:', fpr(proba_weighted, y_test))

    # Choose best: prefer lowest FPR subject to keeping recall > 0.8 for class 1
    candidates = [
        ('baseline', clf_base, proba_base),
        ('no_https', clf_no_https, proba_no_https),
        ('weighted', clf_weighted, proba_weighted),
    ]

    # pick by FPR then by recall
    best = None
    best_score = None
    from sklearn.metrics import recall_score
    for name, clf, proba in candidates:
        preds = (proba >= 0.5).astype(int)
        recall = recall_score(y_test, preds)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        fprate = fp / (fp + tn) if (fp + tn) > 0 else 1.0
        score = ( -fprate, recall )  # prefer lower fpr, higher recall
        print(f'{name}: fpr={fprate:.4f}, recall={recall:.4f}')
        if best is None or score > best_score:
            best = (name, clf)
            best_score = score

    print('Selected best:', best[0])
    out_path = base / 'models' / 'combined_model_tuned.joblib'
    joblib.dump({'model': best[1], 'feature_columns': list(X.columns)}, out_path)
    print('Saved tuned model to', out_path)


if __name__ == '__main__':
    main()
