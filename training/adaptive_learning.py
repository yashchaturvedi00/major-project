"""
Attack Response Training — Adaptive Learning.
Provides recommendations and difficulty labels based on user performance.
"""


def get_weak_tactics(performance_by_tactic):
    """Identify tactics where accuracy is below 50%.

    Args:
        performance_by_tactic: dict from scoring_system.get_performance_by_tactic()

    Returns:
        list of tactic names with low accuracy
    """
    weak = []
    for tactic, stats in performance_by_tactic.items():
        if stats["accuracy"] < 50.0:
            weak.append(tactic)
    return weak


def recommend_next_scenario(scenarios, performance_by_tactic):
    """Recommend the best next scenario based on weak areas.

    Prioritizes scenarios from tactics where the user performs poorly.
    If no weak areas, returns scenarios not yet attempted.

    Args:
        scenarios: list of scenario dicts
        performance_by_tactic: dict from scoring_system.get_performance_by_tactic()

    Returns:
        recommended scenario dict, or None
    """
    weak_tactics = get_weak_tactics(performance_by_tactic)
    attempted_tactics = set(performance_by_tactic.keys())

    # Priority 1: scenarios from weak tactics
    if weak_tactics:
        for s in scenarios:
            if s["tactic"] in weak_tactics:
                return s

    # Priority 2: scenarios from unattempted tactics
    for s in scenarios:
        if s["tactic"] not in attempted_tactics:
            return s

    # Fallback: first scenario
    return scenarios[0] if scenarios else None


def get_difficulty_label(score_summary):
    """Return difficulty label based on accuracy.

    Args:
        score_summary: dict from scoring_system.get_score_summary()

    Returns:
        str: "Beginner", "Intermediate", or "Expert"
    """
    if score_summary["total_attempts"] < 2:
        return "Beginner"
    acc = score_summary["accuracy"]
    if acc >= 80:
        return "Expert"
    elif acc >= 50:
        return "Intermediate"
    return "Beginner"


def get_learning_insights(score_summary, performance_by_tactic):
    """Generate personalized learning feedback.

    Args:
        score_summary: dict from scoring_system.get_score_summary()
        performance_by_tactic: dict from scoring_system.get_performance_by_tactic()

    Returns:
        list of insight strings
    """
    insights = []
    total = score_summary["total_attempts"]

    if total == 0:
        return ["Start a training scenario to begin building your incident response skills!"]

    acc = score_summary["accuracy"]
    if acc >= 80:
        insights.append("🌟 Excellent performance! You demonstrate strong incident response instincts.")
    elif acc >= 50:
        insights.append("📈 Good progress. Keep practicing to sharpen your response decisions.")
    else:
        insights.append("💪 Keep at it! Review the mitigation guidance after each scenario to improve.")

    weak = get_weak_tactics(performance_by_tactic)
    if weak:
        tactic_list = ", ".join(weak)
        insights.append(f"🎯 Focus area: Practice more scenarios in **{tactic_list}** tactics.")

    strong = [t for t, s in performance_by_tactic.items() if s["accuracy"] >= 80]
    if strong:
        tactic_list = ", ".join(strong)
        insights.append(f"✅ Strong in: **{tactic_list}**")

    return insights
