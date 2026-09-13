users = {
    "ai_security_expert": {
        "role": "ai_security",
        "clearance": 4,
        "department": "AI Security",
        "active": True,
    },
    "ml_engineer": {
        "role": "ml_engineer",
        "clearance": 3,
        "department": "Machine Learning",
        "active": True,
    },
    "data_engineer": {
        "role": "data_engineer",
        "clearance": 2,
        "department": "Data Engineering",
        "active": True,
    },
    "research_assistant": {
        "role": "researcher",
        "clearance": 2,
        "department": "Research",
        "active": True,
    },
    "training_bot": {
        "role": "bot_account",
        "clearance": 1,
        "department": "Automation",
        "active": False,
    },
}
resources = [
    ("ai_models", 4),
    ("training_datasets", 3),
    ("data_pipelines", 2),
    ("research_notebooks", 2),
    ("model_artifacts", 4),
    ("synthetic_data", 1),
    ("adversarial_tests", 3),
    ("model_registry", 4),
    ("feature_stores", 2),
    ("public_models", 1),
]
security_levels = ("Open Source", "Internal Research", "Proprietary", "Trade Secret")
blocked_users = {"training_bot", "model_theft", "data_poisoning_acc"}


def check(username, security_level):
    if username not in users:
        return "DENY (User not found)"

    if username in blocked_users:
        return "DENY (User is blocked)"

    user = users[username]

    if user["active"] is False:
        return "DENY (Account inactive)"

    if user["clearance"] >= security_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"


print("-" * 45)

for resource_name, security_level in resources:
    security_name = security_levels[security_level - 1]
    print(f"{resource_name}: {security_name}")

print("-" * 45)

for username in users:
    for resource_name, security_level in resources:
        result = check(
            username,
            security_level,
        )
        print(f"user = {username} | resource = {resource_name} -> {result}")
