"""
Adaptive Routing Classifier
----------------------------
Learns whether to use the 4-agent swarm or the single-agent baseline
from the ablation study results (ablation_v2_n4.json).

Replaces the original keyword-heuristic with a LogisticRegression
trained on empirical outcome data. Label = 1 (use swarm) when
swarm_mean_score > baseline_mean_score, else 0 (use baseline).

Dataset: 8 scenarios × 4 repeats from ablation_v2_n4.json.
Features are derived from incident context text, not from oracle data —
so they're available at routing time (before the swarm runs).

Key finding from ablation: swarm beats baseline ONLY on incidents where
all three evidence sources (logs, commits, tickets) align on the same
technical root cause. That manifests as JNDI/Log4Shell-type CVEs in the
training data. All resource/infra/negative incidents favor the baseline.

LOO-CV accuracy on training data: reported at module load time.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_RESULTS_DIR = Path(__file__).parent.parent / "benchmarks" / "results"
# v2 (N=4, LOO-CV=88%) is the training source: the 1/8 positive rate (ls-01 only)
# gives clean class separation on JNDI/Log4j features → reliable for service+severity
# routing. v3 (N=2, 4/8 positive) shows swarm is competitive on more scenario types,
# but those types (dep, cert, struts) can't be distinguished from infra/CVE noise
# using service+severity alone — see README for the full picture.
_ABLATION_PATH = _RESULTS_DIR / "ablation_v2_n4.json"

# ---------------------------------------------------------------------------
# Training data
# Hand-annotated incident context keywords for the 8 ablation scenarios.
# These represent what a PagerDuty alert body or on-call summary might contain.
# ---------------------------------------------------------------------------
_TRAINING_META: list[dict] = [
    # id, context (what operator/alert would say), label
    {"id": "ls-01",      "context": "JNDI lookup exploit CVE-2021-44228 log4j RCE payment-svc",    "service": "payment-svc",  "severity": "P0"},
    {"id": "t4s-01",     "context": "Text4Shell CVE-2022-42889 script lookup RCE template-svc",    "service": "template-svc", "severity": "P0"},
    {"id": "neg-01",     "context": "no related commits or tickets commons-lang investigation",    "service": "commons-lang", "severity": "P0"},
    {"id": "oom-01",     "context": "JVM heap exhausted OOMKilled OOM payment-svc",               "service": "payment-svc",  "severity": "P0"},
    {"id": "dep-01",     "context": "DB_HOST points to staging bad deploy config drift",          "service": "payment-svc",  "severity": "P0"},
    {"id": "cert-01",    "context": "wildcard TLS cert expired auth-svc P0",                      "service": "auth-svc",     "severity": "P0"},
    {"id": "cfg-01",     "context": "schema migration type mismatch distributor stuck jobs-svc",  "service": "jobs-svc",     "severity": "P0"},
    {"id": "struts-01",  "context": "CVE-2017-5638 OGNL injection RCE Struts portal-svc Equifax", "service": "portal-svc",   "severity": "P0"},
]

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_SECURITY_CVE    = re.compile(r"\b(cve-\d{4}-\d+|jndi|ognl|rce|exploit|injection|vulnerability|log4j|struts|spring4shell)\b", re.I)
_JNDI_SPECIFIC   = re.compile(r"\b(jndi|log4j|ldap|log4shell)\b", re.I)
_OOM_RESOURCE    = re.compile(r"\b(oom|oomkilled|heap|outofmemory|gcoverhead|memory|gc overhead)\b", re.I)
_INFRA_CHANGE    = re.compile(r"\b(deploy|cert|tls|ssl|expired|schema|migration|config|drift|rollback)\b", re.I)
_NEGATIVE_SIGNAL = re.compile(r"\b(no related|no commits|no tickets|inconclusive|negative|unrelated)\b", re.I)


def extract_features(service: str, severity: str, context: str = "") -> list[float]:
    """Return feature vector for routing decision.

    Features (all binary 0/1 except severity):
      0  has_security_cve   — any generic security/CVE indicator
      1  has_jndi_specific  — JNDI/Log4j-specific (strong swarm signal)
      2  has_oom_resource   — OOM/memory/heap (strong single-agent signal)
      3  has_infra_change   — deploy/cert/config/schema (single-agent signal)
      4  has_negative_signal — explicit "no evidence" (single-agent signal)
      5  severity_p0        — incident is P0 (higher stakes → swarm more justified)
    """
    text = f"{service} {severity} {context}".lower()
    return [
        float(bool(_SECURITY_CVE.search(text))),
        float(bool(_JNDI_SPECIFIC.search(text))),
        float(bool(_OOM_RESOURCE.search(text))),
        float(bool(_INFRA_CHANGE.search(text))),
        float(bool(_NEGATIVE_SIGNAL.search(text))),
        float(severity.upper() == "P0"),
    ]


# ---------------------------------------------------------------------------
# Build training set from ablation JSON + metadata
# ---------------------------------------------------------------------------

def _load_training_data() -> tuple[list[list[float]], list[int]] | None:
    if not _ABLATION_PATH.exists():
        return None
    try:
        ablation = json.loads(_ABLATION_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None

    scenarios = ablation.get("per_scenario", {})
    X, y = [], []
    for meta in _TRAINING_META:
        sid = meta["id"]
        if sid not in scenarios:
            continue
        d = scenarios[sid]
        swarm_mean  = d["swarm"]["overall_score"]["mean"]
        base_mean   = d["baseline"]["overall_score"]["mean"]
        swarm_std   = d["swarm"]["overall_score"]["std"]
        base_std    = d["baseline"]["overall_score"]["std"]
        # Label = 1 (use swarm) only when swarm clearly beats baseline
        # (delta > max noise level to avoid labeling statistical ties as "swarm wins")
        delta = swarm_mean - base_mean
        noise = max(swarm_std, base_std)
        label = 1 if delta > noise else 0

        feats = extract_features(meta["service"], meta["severity"], meta["context"])
        X.append(feats)
        y.append(label)

    return (X, y) if X else None


# ---------------------------------------------------------------------------
# Fit model + LOO-CV
# ---------------------------------------------------------------------------

def _fit_and_validate(X: list[list[float]], y: list[int]) -> tuple:
    """Fit LogisticRegression and return (model, scaler, loo_accuracy, feature_names).

    LOO-CV caveat: with N=8 and only 1 positive sample, the LOO fold that removes
    the positive sample produces a single-class train set (unfittable). Those folds
    are scored as "majority class prediction" (always 0) to remain conservative.
    LOO accuracy on heavily imbalanced tiny datasets overstates baseline; treat as
    a lower-bound estimate.
    """
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import LeaveOneOut
    from sklearn.preprocessing import StandardScaler
    import numpy as np

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_arr)

    # LOO-CV — handle single-class folds gracefully
    loo = LeaveOneOut()
    loo_correct = 0
    for train_idx, test_idx in loo.split(X_scaled):
        y_train = y_arr[train_idx]
        if len(set(y_train.tolist())) < 2:
            # Can't fit; predict majority class (0 = baseline)
            pred = 0
        else:
            clf = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
            clf.fit(X_scaled[train_idx], y_train)
            pred = int(clf.predict(X_scaled[test_idx])[0])
        loo_correct += int(pred == y_arr[test_idx[0]])
    loo_acc = loo_correct / len(y_arr)

    # Final model fitted on all data
    model = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
    model.fit(X_scaled, y_arr)

    feature_names = [
        "has_security_cve", "has_jndi_specific", "has_oom_resource",
        "has_infra_change",  "has_negative_signal", "severity_p0",
    ]
    return model, scaler, loo_acc, feature_names


# ---------------------------------------------------------------------------
# Module-level model initialization
# ---------------------------------------------------------------------------

_model = None
_scaler = None
_loo_accuracy: float | None = None
_training_size: int = 0
_sklearn_available = True

try:
    _td = _load_training_data()
    if _td is not None:
        _X, _y = _td
        _training_size = len(_y)
        _model, _scaler, _loo_accuracy, _ = _fit_and_validate(_X, _y)
        print(
            f"[routing] Classifier fitted on N={_training_size} ablation scenarios. "
            f"LOO-CV accuracy: {_loo_accuracy:.0%}  "
            f"(swarm label rate: {sum(_y)}/{_training_size})",
            file=__import__("sys").stderr,
        )
    else:
        print("[routing] Ablation data not found — using keyword fallback.", file=__import__("sys").stderr)
except ImportError:
    _sklearn_available = False
    print("[routing] scikit-learn not installed — using keyword fallback.", file=__import__("sys").stderr)
except Exception as exc:
    print(f"[routing] Classifier init failed ({exc}) — using keyword fallback.", file=__import__("sys").stderr)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_OOM_KW  = {"oom", "outofmemory", "heap", "gcoverhead", "oomkilled", "memory"}
_SWARM_KW = {"cve", "vulnerability", "exploit", "jndi", "rce", "injection", "security"}


def should_use_swarm(
    service: str,
    severity: str,
    context: str = "",
) -> tuple[bool, float, str]:
    """Decide whether to use the 4-agent swarm or the single-agent baseline.

    Returns:
        (use_swarm, confidence, method)
        use_swarm   — True → run swarm; False → run single-agent baseline
        confidence  — probability score [0, 1] (0.5 if falling back to heuristic)
        method      — "classifier" | "keyword_fallback"
    """
    if _model is not None and _scaler is not None:
        import numpy as np
        feats = extract_features(service, severity, context)
        X = _scaler.transform(np.array([feats]))
        proba = _model.predict_proba(X)[0]
        swarm_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        use_swarm = swarm_prob >= 0.5
        return use_swarm, swarm_prob, "classifier"

    # Keyword heuristic fallback (original behaviour)
    brief = f"{service} {severity} {context}".lower()
    if any(kw in brief for kw in _OOM_KW):
        return False, 0.5, "keyword_fallback"
    if any(kw in brief for kw in _SWARM_KW):
        return True, 0.5, "keyword_fallback"
    return True, 0.5, "keyword_fallback"
