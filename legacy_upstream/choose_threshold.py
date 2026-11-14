import joblib
from pathlib import Path
from train_combined import find_csv_paths, load_and_extract, balance_dataframe, url_to_dataframe
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, recall_score
import numpy as np


def find_best_threshold(model, X_test, y_test, min_recall=0.85):
    proba = model.predict_proba(X_test)[:, 1]
    best = None
    best_fpr = 1.0
    for t in np.linspace(0.0, 1.0, 101):
        preds = (proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        recall = recall_score(y_test, preds)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        if recall >= min_recall:
            if fpr < best_fpr:
                best_fpr = fpr
                best = (t, fpr, recall)
    if best is not None:
        return best
    # fallback: return threshold that maximizes recall - fpr
    best_score = -1
    best = (0.5, 1.0, 0.0)
    for t in np.linspace(0.0, 1.0, 101):
        preds = (proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        recall = recall_score(y_test, preds)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        score = recall - fpr
        if score > best_score:
            best_score = score
            best = (t, fpr, recall)
    return best


def main():
    base = Path(__file__).resolve().parent
    csvs = find_csv_paths(base)
    df = load_and_extract(csvs).drop_duplicates(subset=['url']).reset_index(drop=True)
    df_bal = balance_dataframe(df)
    X = url_to_dataframe(df_bal['url'].tolist())
    y = df_bal['label'].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model_path = base / 'models' / 'combined_model_tuned.joblib'
    print('Loading tuned model from', model_path)
    data = joblib.load(model_path)
    clf = data['model']

    best = find_best_threshold(clf, X_test, y_test, min_recall=0.88)
    print('Chosen threshold (min recall 0.88):', best)
    # also try stricter recall 0.9
    best2 = find_best_threshold(clf, X_test, y_test, min_recall=0.9)
    print('Chosen threshold (min recall 0.90):', best2)

    # Save chosen threshold file
    chosen = best[0] if best is not None else 0.5
    with open(base / 'models' / 'threshold.txt', 'w') as f:
        f.write(str(chosen))
    print('Saved threshold to models/threshold.txt')


if __name__ == '__main__':
    main()
