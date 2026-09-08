"""
explainability.py
-----------------
Explainable AI (XAI) and Token-Level Attribution Engine for PhishGuard.
Generates legal-grade visual and textual evidence for Section 65B compliance.
"""

import html
import re


def generate_token_heatmap_html(text, attributions):
    """
    Renders an HTML snippet with highlighted tokens showing why the AI flagged the text.
    """
    if not text:
        return ""

    clean_text = html.escape(text)
    if not attributions:
        return f'<div class="xai-heatmap" style="background: #f8fafc; padding: 14px; border-radius: 8px; font-family: monospace; font-size: 13px; color: #475569; border: 1px solid #e2e8f0;">{clean_text}</div>'

    highlighted = clean_text
    for word, score in attributions:
        if not word or len(word) < 2:
            continue
        if score >= 0.3:
            bg_color = "#fee2e2"
            border_color = "#fca5a5"
            text_color = "#991b1b"
        elif score >= 0.15:
            bg_color = "#fef3c7"
            border_color = "#fcd34d"
            text_color = "#92400e"
        else:
            bg_color = "#d1fae5"
            border_color = "#a7f3d0"
            text_color = "#065f46"

        pattern = re.compile(r'\b(' + re.escape(word) + r')\b', re.IGNORECASE)
        replacement = f'<mark style="background: {bg_color}; border: 1px solid {border_color}; color: {text_color}; padding: 2px 7px; border-radius: 4px; font-weight: 700;">\\1 <span style="font-size: 9px; opacity: 0.95;">+{int(score*100)}%</span></mark>'
        highlighted = pattern.sub(replacement, highlighted)

    return f'<div class="xai-heatmap" style="background: #f8fafc; padding: 14px; border-radius: 8px; font-family: monospace; font-size: 13px; color: #0f172a; border: 1px solid #e2e8f0; line-height: 2.2;">{highlighted}</div>'


def format_section_65b_legal_xai_summary(attributions, threat_category):
    """
    Synthesizes formal text explanation for the Section 65B Court Certificate.
    """
    if not attributions:
        return "No lexical anomalies or coercive social-engineering tokens identified."

    top_cues = [f"'{word}' (+{int(score*100)}% salience)" for word, score in attributions[:4]]
    return f"Explainable AI Lexical Attribution: High-salience coercion tokens identified [{', '.join(top_cues)}] demonstrating calculated linguistic intent consistent with {threat_category}."
