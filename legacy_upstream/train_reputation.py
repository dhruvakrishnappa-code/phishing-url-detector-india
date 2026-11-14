import joblib
from pathlib import Path
from train_combined import find_csv_paths, load_and_extract, balance_dataframe, url_to_dataframe
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


def main():
    base = Path(__file__).resolve().parent
    csvs = find_csv_paths(base)
    print('Loading CSVs:', len(csvs))
    df = load_and_extract(csvs)
    print('Total:', len(df))
    df = df.drop_duplicates(subset=['url']).reset_index(drop=True)
    df_bal = balance_dataframe(df)

    X = url_to_dataframe(df_bal['url'].tolist())
    y = df_bal['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Retrain weighted model (chosen earlier) but with domain_reputation feature included
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, class_weight={0:2, 1:1})
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    print('\nClassification report:')
    print(classification_report(y_test, preds))
    print('Confusion matrix:')
    print(confusion_matrix(y_test, preds))

    out_path = base / 'models' / 'combined_model_reputation.joblib'
    joblib.dump({'model': clf, 'feature_columns': list(X.columns)}, out_path)
    print('Saved model with reputation to', out_path)


if __name__ == '__main__':
    main()
