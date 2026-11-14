"""Train the local URL classifier (adapted from the upstream train.py).

  python scripts/build_dataset.py        # builds data/dataset.csv
  python train.py --data data/dataset.csv
Writes models/model.joblib and models/model_metadata.json with REAL measured metrics.
"""
import argparse, datetime, json, os, warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
import joblib, pandas as pd, sklearn, tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from features import extract_host_features, HOST_FEATURE_COLUMNS


def load_dataset(path):
    df = pd.read_csv(path)
    if 'url' not in df.columns or 'label' not in df.columns:
        raise ValueError('CSV must have `url` and `label` columns')
    return df[['url', 'label']].dropna()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True, help='CSV with columns url,label (1 = phishing)')
    ap.add_argument('--out', default='models/model.joblib')
    ap.add_argument('--source-note', default='Phishing.Database ACTIVE (MIT) + Tranco top-50k; see ADAPTATIONS.md')
    args = ap.parse_args()
    df = load_dataset(args.data)
    X = pd.DataFrame([extract_host_features(u) for u in df['url']])[HOST_FEATURE_COLUMNS]
    y = df['label'].astype(int).values
    groups = [tldextract.extract(u).registered_domain or u for u in df['url']]
    # split by registered domain so the same site never appears in both train and test
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(X, y, groups))
    clf = RandomForestClassifier(n_estimators=100, min_samples_leaf=5, random_state=42, n_jobs=-1)
    clf.fit(X.iloc[tr], y[tr])
    pred = clf.predict(X.iloc[te]); prob = clf.predict_proba(X.iloc[te])[:, 1]
    tn, fp, fn, tp = confusion_matrix(y[te], pred).ravel()
    metrics = {
        'accuracy': round(accuracy_score(y[te], pred), 4),
        'precision': round(precision_score(y[te], pred), 4),
        'recall': round(recall_score(y[te], pred), 4),
        'f1': round(f1_score(y[te], pred), 4),
        'roc_auc': round(roc_auc_score(y[te], prob), 4),
        'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        'train_rows': int(len(tr)), 'test_rows': int(len(te)),
    }
    print(json.dumps(metrics, indent=2))
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({'model': clf, 'feature_columns': HOST_FEATURE_COLUMNS}, args.out, compress=3)
    meta = {
        'trained_at_utc': datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'algorithm': 'RandomForestClassifier(n_estimators=100, min_samples_leaf=5)',
        'sklearn_version': sklearn.__version__,
        'dataset': args.source_note,
        'rows': int(len(df)), 'phishing_rows': int(y.sum()),
        'evaluation': 'held-out 20% split grouped by registered domain',
        'metrics': metrics,
    }
    with open(os.path.join(os.path.dirname(args.out), 'model_metadata.json'), 'w') as f:
        json.dump(meta, f, indent=2)
    print('saved', args.out)


if __name__ == '__main__':
    main()
