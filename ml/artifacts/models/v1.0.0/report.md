# MailSherlock Phishing Classifier v1.0.0 - evaluation report

- Trained: 2026-10-05T05:08:53+00:00
- Selected candidate: `lr_text` - TF-IDF words + character 3-5 grams + logistic regression
- Dataset version: 2026.10-pp-sa; feature version: f1
- Decision threshold: **0.5544** (lowest validation threshold with false-positive rate <= 1%)

## Candidate comparison (validation split)

| Candidate | Eligible | Recall @ FPR<=1% | PR-AUC | ROC-AUC | Train (s) |
|---|---|---|---|---|---|
| lr_words | yes | 97.44% | 0.9961 | 0.9952 | 3.52 |
| lr_text | yes | 97.44% | 0.9976 | 0.9973 | 14.26 |
| lr_hybrid | no - contradicts priors (max_subdomain_depth, form_present) | 97.63% | 0.9961 | 0.9966 | 18.01 |
| svm_hybrid | no - not decomposable | 97.63% | 0.996 | 0.9971 | 19.31 |
| nb_words | no - not decomposable | 97.24% | 0.9935 | 0.9904 | 3.59 |
| gbm_structural | no - not decomposable | 81.46% | 0.9817 | 0.9811 | 1.41 |

## Held-out test split

| Metric | Tuned threshold | Threshold 0.5 |
|---|---|---|
| precision | 99.54% | 99.32% |
| recall | 95.98% | 97.10% |
| f1 | 97.73% | 98.20% |
| accuracy | 98.07% | 98.45% |
| false positive rate | 0.34% | 0.51% |
| false negative rate | 4.02% | 2.90% |
| ROC-AUC | 0.9996 | |
| PR-AUC | 0.9995 | |

Confusion matrix (n=1035): TP 430 | FP 2 | TN 585 | FN 18

## Modern challenge set (evaluation only)

22 legitimate and 12 phishing hand-written modern emails. False positives: **18 / 22**; missed phishing: **2 / 12**.

| Subject | Label | P(phishing) | Predicted |
|---|---|---|---|
| Reset your password | legitimate | 0.970 | phishing **(error)** |
| Your verification code | legitimate | 0.952 | phishing **(error)** |
| Security alert: new sign-in to your account | legitimate | 0.986 | phishing **(error)** |
| Your Amazon.in order has shipped | legitimate | 0.845 | phishing **(error)** |
| Invoice INV-0042 from Acme Design Studio | legitimate | 0.737 | phishing **(error)** |
| Payment received - thank you | legitimate | 0.995 | phishing **(error)** |
| Your monthly statement is ready | legitimate | 0.971 | phishing **(error)** |
| Weekly digest: 14 new posts in Rust Users | legitimate | 0.302 | legitimate |
| Your subscription will renew soon | legitimate | 0.838 | phishing **(error)** |
| Action required: confirm your email address | legitimate | 0.997 | phishing **(error)** |
| Interview schedule - Security Analyst Intern | legitimate | 0.710 | phishing **(error)** |
| Re: lab report submission | legitimate | 0.493 | legitimate |
| Flash sale: 40% off everything this weekend | legitimate | 0.173 | legitimate |
| Your Uber receipt | legitimate | 0.919 | phishing **(error)** |
| GitHub: [repo] Dependabot alert | legitimate | 0.600 | phishing **(error)** |
| Your account has been locked after failed sign-ins | legitimate | 0.972 | phishing **(error)** |
| Reminder: dentist appointment tomorrow | legitimate | 0.899 | phishing **(error)** |
| Team offsite - travel details | legitimate | 0.685 | phishing **(error)** |
| Your PayPal receipt | legitimate | 0.993 | phishing **(error)** |
| Two-factor authentication enabled | legitimate | 0.908 | phishing **(error)** |
| Delivery update: your parcel is out for delivery | legitimate | 0.830 | phishing **(error)** |
| Overdue library book | legitimate | 0.282 | legitimate |
| Your mailbox is almost full | phishing | 0.962 | phishing |
| Payment declined - update your billing information | phishing | 0.992 | phishing |
| Unusual activity detected | phishing | 0.978 | phishing |
| Re: outstanding invoice | phishing | 0.969 | phishing |
| Shared document: Q3 Salary Revision.pdf | phishing | 0.952 | phishing |
| Congratulations! You have won | phishing | 0.979 | phishing |
| Urgent request | phishing | 0.707 | phishing |
| IT: mandatory MFA re-enrollment | phishing | 0.434 | legitimate **(error)** |
| Your package is on hold | phishing | 0.540 | legitimate **(error)** |
| Tax refund notification | phishing | 0.975 | phishing |
| Apple ID locked | phishing | 0.972 | phishing |
| Job offer - work from home | phishing | 0.958 | phishing |

Validation (threshold selection split): recall 97.44%, FPR 0.53%, precision 99.40%.

## Strongest global weights (leakage audit)

| Toward phishing | Toward legitimate |
|---|---|
| word: `your` (4.7693) | word: `the` (-3.0558) |
| word: `de` (3.0255) | word: `it` (-2.03) |
| word: `you` (2.7319) | word: `of` (-1.8457) |
| char: `you` (2.702) | word: `that` (-1.7862) |
| char: ` yo` (2.6989) | char: `the` (-1.6997) |
| char: ` you` (2.6943) | word: `on` (-1.6925) |
| char: `your` (2.5999) | char: `'s ` (-1.5476) |
| char: ` your` (2.5839) | char: ` the` (-1.5232) |
| char: `our ` (2.5126) | word: `urltoken` (-1.5212) |
| char: `ur ` (2.4999) | char: ` th` (-1.4815) |
| char: `your ` (2.4921) | word: `so` (-1.3992) |
| char: `our` (2.3457) | word: `but` (-1.3929) |
| word: `unsubscribe` (2.2261) | char: `...` (-1.3656) |
| char: ` 0 ` (2.0811) | word: `linux` (-1.3564) |
| word: `this email` (1.719) | word: `in the` (-1.3227) |
