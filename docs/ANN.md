# ANN strength estimate

## Where it is applied

The ANN runs in the local `/api/check` password preview used by both Add Account and Update Account. It returns a second weak/fair/strong estimate, a mapped 0-100 score and a class confidence. The UI displays it beside the rule-based estimate.

The rule-based score remains authoritative: it is the value saved for an account and the value used by the existing risk formula. The ANN output is returned only in the live preview / save response and is not used to lower a reuse, breach or age risk. This makes the ANN visible as an additional feature without silently changing existing decisions.

## Model and features

`reuse_analyzer/ann.py` implements a one-hidden-layer, 12-unit feed-forward neural network with sigmoid hidden units and a three-class softmax output. Inference uses Python's standard library; no ML package or runtime network access is required.

Its 12 inputs describe shape only: length, available character-pool size, lower/upper/digit/symbol ratios, unique-character ratio, repeated and sequential character ratios, alphabetic ratio, and longest digit/symbol runs. The input password is examined transiently. No training, model artifact, DB row or API response contains the submitted password text from this feature.

## Dataset and training

`reuse_analyzer/train_ann.py` generates 2,100 synthetic password patterns using fixed word fragments, simple mutation patterns, random strings and multiword passphrases. It extracts feature vectors in memory and writes only those numeric features plus a synthetic weak/fair/strong class label to `reuse_analyzer/data/ann_strength_synthetic.csv`. No real account passwords, leaked-password corpus or user records are used.

The trainer uses a fixed seed and an 80/20 stratified train/validation split. The checked-in model was trained for 22 epochs and reached 99.76% validation accuracy on the 420 held-out synthetic examples. This figure only measures agreement with the generator's constructed labels; it is **not** a security benchmark or accuracy estimate for real users' passwords. The model is deliberately experimental and should not be presented as validated against real-world attacker guesses.

Rebuild both artifacts with:

```powershell
python -m reuse_analyzer.train_ann
```

The script needs only Python's standard library. It writes the trained JSON weights to `reuse_analyzer/data/ann_strength_model.json` and regenerates the feature-only CSV. No datasets need to be downloaded to run the app.
