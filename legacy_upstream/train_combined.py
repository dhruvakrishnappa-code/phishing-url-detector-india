import os
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from features import url_to_dataframe


def find_csv_paths(base_path: Path):
    return [p for p in base_path.rglob('*.csv')]


def find_url_column(df: pd.DataFrame):
    for col in df.columns:
        if 'url' == col.lower() or 'url' in col.lower():
            return col
    return None


def find_label_column(df: pd.DataFrame):
    candidates = ['label', 'classlabel', 'class', 'status', 'phish', 'labelled', 'labelled_status']
    for col in df.columns:
        if col.lower() in candidates:
            return col
    # fallback: last column if it looks like labels
    last = df.columns[-1]
    return last


def normalize_label(val):
    if pd.isna(val):
        return None
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ('phishing', 'phish', 'malicious', '1', 'true', 't', 'y', 'yes'):
            return 1
        if s in ('legitimate', 'legit', 'benign', '0', 'false', 'f', 'n', 'no'):
            return 0
        # numeric-like string
        try:
            iv = int(float(s))
            return 1 if iv != 0 else 0
        except Exception:
            return None
    try:
        iv = int(float(val))
        return 1 if iv != 0 else 0
    except Exception:
        return None


def load_and_extract(csv_paths):
    rows = []
    for p in csv_paths:
        try:
            df = pd.read_csv(p, low_memory=False)
        except Exception as e:
            print(f'Failed to read {p}: {e}')
            continue
        url_col = find_url_column(df)
        if url_col is None:
            print(f'Skipping {p} — no URL column found')
            continue
        label_col = find_label_column(df)
        print(f'Processing {p.name}: url_col={url_col}, label_col={label_col}')
        for _, r in df[[url_col, label_col]].iterrows():
            url = r[url_col]
            lab = normalize_label(r[label_col])
            if pd.isna(url) or lab is None:
                continue
            rows.append((str(url), int(lab)))
    if not rows:
        return pd.DataFrame(columns=['url', 'label'])
    out = pd.DataFrame(rows, columns=['url', 'label'])
    # compute domain reputation (fraction legitimate per registered domain)
    try:
        import tldextract
        regs = out['url'].apply(lambda u: tldextract.extract(u).registered_domain if pd.notna(u) else '')
        out['_registered_domain'] = regs
        rep = out.groupby('_registered_domain')['label'].agg(['mean', 'count']).reset_index()
        # require a minimum number of samples for a trusted reputation value
        MIN_COUNT_FOR_REPUTATION = 50
        rep_map = {r['_registered_domain']: r['mean'] for _, r in rep.iterrows() if r['count'] >= MIN_COUNT_FOR_REPUTATION}
        # set into features module if available
        try:
            from features import set_domain_reputation_map
            set_domain_reputation_map(rep_map)
        except Exception:
            pass
    except Exception:
        pass
    return out


def balance_dataframe(df: pd.DataFrame):
    counts = df['label'].value_counts()
    if len(counts) < 2:
        return df
    min_count = counts.min()
    parts = []
    for lbl in counts.index:
        sub = df[df['label'] == lbl]
        parts.append(sub.sample(min_count, random_state=42))
    return pd.concat(parts).sample(frac=1, random_state=42).reset_index(drop=True)


def main():
    base = Path(__file__).resolve().parent
    csvs = find_csv_paths(base)
    print('Found CSVs:', [str(p) for p in csvs])

    df = load_and_extract(csvs)
    print('Total examples after loading:', len(df))
    if df.empty:
        print('No data to train on. Provide CSVs with URL and label columns.')
        return

    df = df.drop_duplicates(subset=['url'])
    print('After dedup:', len(df))

    # Balance classes by downsampling majority
    df_bal = balance_dataframe(df)
    print('After balancing:', df_bal['label'].value_counts().to_dict())

    X = url_to_dataframe(df_bal['url'].tolist())
    y = df_bal['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    print('\nClassification report:')
    print(classification_report(y_test, preds))
    print('Confusion matrix:')
    print(confusion_matrix(y_test, preds))

    models_dir = base / 'models'
    models_dir.mkdir(exist_ok=True)
    out_path = models_dir / 'combined_model.joblib'
    joblib.dump({'model': clf, 'feature_columns': list(X.columns)}, out_path)
    print(f'Model saved to {out_path}')


if __name__ == '__main__':
    main()
