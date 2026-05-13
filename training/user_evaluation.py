"""
Attack Response Training — User Evaluation.
Evaluates the user's response and provides structured feedback with MITRE context.
"""


def evaluate_response(scenario, selected_option_id):
    """Evaluate a user's response to a training scenario.

    Args:
        scenario: dict from scenario_engine.SCENARIOS
        selected_option_id: str, the option ID selected (e.g. "A")

    Returns:
        dict with evaluation results including correctness, explanation,
        consequences, mitigation guidance, and MITRE context.
    """
    selected_option = None
    correct_option = None

    for opt in scenario["options"]:
        if opt["id"] == selected_option_id:
            selected_option = opt
        if opt["is_correct"]:
            correct_option = opt

    if not selected_option:
        return {"error": f"Invalid option ID: {selected_option_id}"}

    is_correct = selected_option["is_correct"]

    return {
        "is_correct": is_correct,
        "selected_option_id": selected_option_id,
        "selected_option_text": selected_option["text"],
        "correct_option_id": correct_option["id"],
        "correct_option_text": correct_option["text"],
        "explanation": selected_option["explanation"],
        "consequences": selected_option["consequences"],
        "mitigation_guidance": scenario["mitigation_guidance"],
        "real_world_example": scenario.get("real_world_example", ""),
        "mitre_context": {
            "technique_id": scenario["mitre_id"],
            "technique_name": scenario["mitre_name"],
            "tactic": scenario["tactic"],
            "kill_chain_stage": scenario["kill_chain_stage"],
            "severity": scenario["severity"],
        },
    }
