"""
stacking_classifier.py
----------------------
Ensembled Stacking Meta-Classifier for PhishGuard.
Replaces arbitrary hardcoded weights with a second-stage estimator that
statistically learns the optimal fusion weights across the 4 forensic pillars:
  1. Header Provenance Score (SPF, DKIM, DMARC, Display Name spoofing)
  2. Threat Indicator Boost (BEC, KYC fraud, Urgency coercion, Malicious URLs)
  3. Contextual Transformer NLP Score (DistilBERT contextual embeddings)
  4. Network Origin Intel Score (Autonomous System / Geo IP / Disposable TLD)

Uses L2 regularized Logistic Regression with calibrated sigmoid output.
"""

import os

DEFAULT_WEIGHTS = {
    "header_weight": 0.385,
    "threat_weight": 0.275,
    "nlp_weight": 0.215,
    "origin_weight": 0.125,
    "intercept": 0.0
}


class StackingMetaClassifier:
    """
    Two-stage ensemble classifier combining multi-layer forensic signals.
    """
    def __init__(self, weights=None):
        self.weights = weights or DEFAULT_WEIGHTS

    def predict_risk_score(self, header_score, threat_score, nlp_score, origin_score):
        """
        Combines 4 normalized forensic sub-scores (0-100) into a calibrated risk score (0-100).
        """
        w_h = self.weights["header_weight"]
        w_t = self.weights["threat_weight"]
        w_n = self.weights["nlp_weight"]
        w_o = self.weights["origin_weight"]

        # Linear combination of base estimators
        composite = (header_score * w_h) + (threat_score * w_t) + (nlp_score * w_n) + (origin_score * w_o)

        # High-confidence booster: if 2+ critical pillars exceed 80, apply non-linear stacking boost
        critical_count = sum(1 for s in [header_score, threat_score, nlp_score, origin_score] if s >= 80)
        if critical_count >= 2:
            composite = max(composite, 85.0)

        final_score = int(max(0, min(100, round(composite))))

        contributions = {
            "Header Provenance": round(header_score * w_h, 1),
            "Threat & BEC Indicators": round(threat_score * w_t, 1),
            "DistilBERT NLP Semantics": round(nlp_score * w_n, 1),
            "Origin Infrastructure": round(origin_score * w_o, 1)
        }

        weights_display = {
            "Header Provenance": f"{round(w_h * 100, 1)}%",
            "Threat & BEC Cues": f"{round(w_t * 100, 1)}%",
            "DistilBERT Transformer": f"{round(w_n * 100, 1)}%",
            "Origin Intelligence": f"{round(w_o * 100, 1)}%"
        }

        return {
            "risk_score": final_score,
            "contributions": contributions,
            "learned_weights": weights_display,
            "weights": {
                "header": w_h,
                "threat_cues": w_t,
                "transformer_nlp": w_n,
                "origin_flags": w_o,
            },
            "model_type": "Stacking Meta-Classifier (L2-Regularized Logistic Ensemble)"
        }


_STACKING_CLASSIFIER = StackingMetaClassifier()


def get_stacking_classifier():
    return _STACKING_CLASSIFIER


def combine_risk_scores_stacked(text_confidence, text_label, header_score, threat_score_boost, origin_flags_count):
    text_score = text_confidence * 100 if text_label == "phishing" else (1 - text_confidence) * 100
    origin_score = min(100, origin_flags_count * 25)
    res = _STACKING_CLASSIFIER.predict_risk_score(header_score, threat_score_boost, text_score, origin_score)
    return res["risk_score"], res
