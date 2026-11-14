import joblib
from pathlib import Path
import pandas as pd
import numpy as np
from train_combined import find_csv_paths, load_and_extract, balance_dataframe, url_to_dataframe
from sklearn.model_selection import train_test_split


def main():
    base = Path(__file__).resolve().parent
    csvs = find_csv_paths(base)
    print('Found CSVs:', [str(p) for p in csvs])

    df = load_and_extract(csvs)
    print('Total examples:', len(df))
    df = df.drop_duplicates(subset=['url']).reset_index(drop=True)
    print('After dedup:', len(df))

    df_bal = balance_dataframe(df)
    print('Balanced counts:', df_bal['label'].value_counts().to_dict())

    X = url_to_dataframe(df_bal['url'].tolist())
    y = df_bal['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # prefer enriched/tuned/reputation models if available (match server behavior)
    MODEL_PATH = None
    for candidate in ('combined_model_enriched.joblib', 'combined_model_reputation.joblib', 'combined_model_tuned.joblib', 'combined_model.joblib', 'model.joblib'):
        p = base / 'models' / candidate
        if p.exists():
            MODEL_PATH = p
            break
    if MODEL_PATH is None:
        MODEL_PATH = base / 'models' / 'combined_model.joblib'
    print('Loading model from', MODEL_PATH)
    model_data = joblib.load(MODEL_PATH)
    clf = model_data['model']
    feat_cols = model_data.get('feature_columns', list(X.columns))

    # predict probabilities on test set
    proba = clf.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)

    # false positives: true label 0, predicted 1
    fp_idx = np.where((y_test == 0) & (preds == 1))[0]
    fn_idx = np.where((y_test == 1) & (preds == 0))[0]
    print(f'False positives: {len(fp_idx)}, False negatives: {len(fn_idx)}')

    # Show top FP examples with probabilities and feature values
    n_show = 10
    print('\nSample false positives (label=0 predicted=1):')
    for i in fp_idx[:n_show]:
        print(f'- URL: {df_bal.url.iloc[X_test.index[i]] if hasattr(X_test, "index") else "(unknown)"}')
        print(f'  prob={proba[i]:.3f} feats={{')
        row = X_test.iloc[i]
        for c, v in zip(feat_cols, row):
            print(f'    {c}: {v}')
        print('  }')

    # feature importances
    try:
        importances = clf.feature_importances_
        fi = sorted(zip(feat_cols, importances), key=lambda x: x[1], reverse=True)
        print('\nTop feature importances:')
        for f, imp in fi[:10]:
            print(f'  {f}: {imp:.4f}')
    except Exception as e:
        print('Could not read feature importances:', e)


if __name__ == '__main__':
    main()
