# A One-Line Rule against Ten Models on a Popular Phishing Benchmark

**What near-perfect accuracy on PhiUSIIL really measures**

Course project for ADY201m (FPT University), Group 10
Nguyễn Đức Hùng (SE201567), Cao Huy (SE201674)
Supervisor: Lê Võ Minh Thư

---

## In one paragraph

Papers that use the PhiUSIIL phishing URL dataset (UCI id 967) report 95% to 99.8% accuracy with deep networks.
We show that a hand-written two-condition rule, *flag a URL if it does not start with `https://www.` or if it has a path after the domain*, reaches **99.72% accuracy, catches 99.34% of phishing URLs and raises no false alarm** on the same test sets.
The reason is that every legitimate URL in the dataset is a bare homepage that starts with `https://www.`, while most phishing URLs do not.
Ten models from four families all reach a ROC-AUC of 0.9999 to 1.0000 with the full feature set, but on phishing **homepages** and with features that **cannot see the prefix**, the best model catches only about 26% of phishing URLs at 1% false alarms (ROC-AUC 0.66 to 0.74).
When the test TLDs were never seen in training, false alarms on legitimate URLs rise from 1% to 7% to 18% for address features.

## Research questions

1. How do the two classes differ in URL shape, top-level domain and the similarity index?
2. Which of ten models from four families separates phishing from legitimate URLs best under a stratified split, and can the models be told apart?
3. How much of the near-perfect score is left when we remove the similarity index, keep only address features, hide the `https://www.` prefix, replace the models with a one-line rule, and test on unseen domains or unseen TLDs?

## What this project does

| Area | What we did |
|---|---|
| Data audit | Removed 425 duplicate URLs; found errors in the author-supplied columns (`URLLength` is the true length minus one for every legitimate URL, `NoOfSubDomain` counts `www.`, `IsDomainIP` flags 30 host names that only contain an IP) |
| Shortcuts | Measured three shortcuts: the similarity index (100 for every legitimate URL), the `https://www.` prefix (100% of legitimate vs 2.43% of phishing) and the path (0% of legitimate vs 59.7% of phishing); phishing pages are also nearly empty when saved |
| Prefix-blind features | Re-computed 14 address features after stripping `http(s)://` and `www.` |
| Baselines | Three one-line rules that need no training |
| Models | Logistic regression, linear SVM, k-NN, decision tree, random forest, extra trees, HistGradientBoosting, LightGBM, XGBoost, small MLP |
| Feature ladder | Seven feature sets, from all 50 author features down to 14 prefix-blind features |
| Evaluation | Phishing caught at a fixed 1% false-alarm budget (threshold set on validation), ROC-AUC, PR-AUC, Brier score, accuracy, F1; five seeds; scored on the whole test set and on homepages only |
| Statistics | McNemar tests with Holm correction, bootstrap confidence intervals |
| Extra checks | Split by registered domain, hyper-parameter tuning, unseen TLDs, model size and scoring time, permutation importance |

## Main results

| Result | Number |
|---|---|
| Two-condition rule, test set (mean of five seeds) | 99.72% accuracy, 99.34% caught, 0 false alarms |
| Ten models, all 50 features | ROC-AUC 0.9999 to 1.0000, accuracy 99.89% to 100% |
| Ten models, 21 address features only | best 99.65% caught at 1% false alarms |
| Ten models, 14 prefix-blind features | ROC-AUC about 0.886, best 70.14% caught |
| Same, homepages only | ROC-AUC 0.663 to 0.737, best 26.0% caught |
| Split by registered domain | caught drops by at most 0.98 points |
| Hyper-parameter tuning | homepage ROC-AUC gain at most 0.0004 |
| Unseen TLDs, address features | false alarms 7.4% to 18.4% instead of 1% |
| Unseen TLDs, prefix-blind features | false alarms 38.7% to 43.5% |
| Smallest model on address features | about 2.4 kB, as good as a 20 MB random forest |

## Limitations

- The dataset has no time column, so we could not test how long a filter stays useful as attackers change.
- We did not collect new URLs; every conclusion is about PhiUSIIL as published.
- The UCI page does not describe how the two classes were collected or how `URLSimilarityIndex` is computed; our explanation of the shortcuts (different sources for the two classes) is inferred from the data, for example from the `FILENAME` prefixes.
- The prefix-blind features are simple counts. A stronger model of the domain name (character n-grams, language models) might do better on homepages.
- Country-code TLDs tell us where a domain was registered, not where the attacker or the server is.

## Repository layout

```
Data/                 world_countries.geojson (Natural Earth, public domain); put the PhiUSIIL CSV here
Source Code/          six notebooks and style.py
Outputs/              tables (CSV) and results written by the notebooks
Figures/              PNG and PDF figures
Paper/                LaTeX tables and figures used in the paper
SQL/                  the SQL queries of notebook 3
```

| Notebook | Content |
|---|---|
| 1. Business Understanding and Analytic Approach | context, research gap, research questions, the three shortcuts |
| 2. Data Collection, Understanding, Preparation | data dictionary, cleaning, prefix-blind features, splits, leakage checks |
| 3. Data Analysis with SQL | descriptive questions in DuckDB, checked against pandas |
| 4. Data Analysis with Python | distributions, correlations, TLD shift, file order, geography |
| 5. Data Visualization | paper figures and the descriptive table |
| 6. Modeling and Model Comparison | rules, ten models, feature ladder, tests, four extra checks |

## How to reproduce

1. Install Python 3.13 and the packages:
   ```
   pip install -r requirements.txt
   ```
2. Download `PhiUSIIL_Phishing_URL_Dataset.csv` from the UCI Machine Learning Repository
   (https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) and put it in `Data/`.
3. Open `Source Code/` and run the notebooks in the order **1, 2, 3, 4, 6, 5**.
   Notebook 5 reads the model results of notebook 6.
   Notebook 6 takes about 1 to 1.5 hours on a two-core laptop the first time; afterwards it reads the saved results (`RERUN = False`).

Two large generated files are not in the repository and are re-created by the notebooks:
`Outputs/phishing_model_table.parquet` (notebook 2) and `Outputs/phishing.duckdb` (notebook 3).

## Data and licence

- PhiUSIIL Phishing URL Dataset: Prasad, A., Chandra, S. (2024), UCI Machine Learning Repository, CC BY 4.0.
  Paper: *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning*, Computers & Security 136, 103545. https://doi.org/10.1016/j.cose.2023.103545
- Country borders: Natural Earth 1:110m admin-0 countries (public domain).
- Our code is released under the MIT licence (see `LICENSE`).
