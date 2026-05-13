"""
Attack Response Training — Scoring System.
Tracks user performance across training scenarios using Streamlit session state.
"""
import streamlit as st
from datetime import datetime


SEVERITY_POINTS = {"High": 30, "Medium": 20, "Low": 10}


def init_scoring():
    """Initialize scoring in session state if not present."""
    if "training_score" not in st.session_state:
        st.session_state.training_score = {
            "attempts": [],
            "total_correct": 0,
            "total_attempts": 0,
            "total_points": 0,
        }


def record_attempt(scenario_id, is_correct, severity, tactic):
    """Record a training attempt.

    Args:
        scenario_id: str identifier
        is_correct: bool
        severity: str High/Medium/Low
        tactic: str MITRE tactic name
    """
    init_scoring()
    score = st.session_state.training_score
    points = SEVERITY_POINTS.get(severity, 10) if is_correct else 0

    score["attempts"].append({
        "scenario_id": scenario_id,
        "is_correct": is_correct,
        "severity": severity,
        "tactic": tactic,
        "points": points,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    score["total_attempts"] += 1
    if is_correct:
        score["total_correct"] += 1
    score["total_points"] += points


def get_score_summary():
    """Return summary of user performance."""
    init_scoring()
    score = st.session_state.training_score
    total = score["total_attempts"]
    correct = score["total_correct"]
    accuracy = round((correct / total * 100), 1) if total > 0 else 0.0

    return {
        "total_attempts": total,
        "total_correct": correct,
        "accuracy": accuracy,
        "total_points": score["total_points"],
    }


def get_performance_by_tactic():
    """Return accuracy breakdown by MITRE tactic."""
    init_scoring()
    tactics = {}
    for attempt in st.session_state.training_score["attempts"]:
        tactic = attempt["tactic"]
        if tactic not in tactics:
            tactics[tactic] = {"correct": 0, "total": 0}
        tactics[tactic]["total"] += 1
        if attempt["is_correct"]:
            tactics[tactic]["correct"] += 1

    result = {}
    for tactic, counts in tactics.items():
        acc = round(counts["correct"] / counts["total"] * 100, 1)
        result[tactic] = {"correct": counts["correct"], "total": counts["total"], "accuracy": acc}
    return result


def get_history():
    """Return full attempt history."""
    init_scoring()
    return st.session_state.training_score["attempts"]


def reset_scores():
    """Clear all scoring data."""
    st.session_state.training_score = {
        "attempts": [],
        "total_correct": 0,
        "total_attempts": 0,
        "total_points": 0,
    }
