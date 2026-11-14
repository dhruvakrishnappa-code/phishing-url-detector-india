import os
from pathlib import Path
import joblib
from train_combined import find_csv_paths, load_and_extract, balance_dataframe, url_to_dataframe
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


def main():
    # enable enrichment for this run (small sample)
    os.environ['USE_ENRICH'] = '1'
    base = Path(__file__).resolve().parent
    csvs = find_csv_paths(base)
    df = load_and_extract(csvs)
    df = df.drop_duplicates(subset=['url']).reset_index(drop=True)

    # for speed/demo, take a small balanced sample
    df_bal = balance_dataframe(df)
    # limit to 200 per class if available
    max_per = 200
    parts = []
    for lbl in [0, 1]:
        sub = df_bal[df_bal['label'] == lbl]
        parts.append(sub.sample(min(len(sub), max_per), random_state=42))
    import pandas as pd
    demo = pd.concat(parts, ignore_index=True)

    X = url_to_dataframe(demo['url'].tolist())
    y = demo['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, class_weight={0:2, 1:1})
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    print('\nClassification report (enriched small sample):')
    print(classification_report(y_test, preds))
    print('Confusion matrix:')
    print(confusion_matrix(y_test, preds))

    out_path = base / 'models' / 'combined_model_enriched.joblib'
    joblib.dump({'model': clf, 'feature_columns': list(X.columns)}, out_path)
    print('Saved enriched small model to', out_path)


if __name__ == '__main__':
    main()
