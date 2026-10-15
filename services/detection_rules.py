SUSPICIOUS_USER_AGENT_MARKERS = ("nmap", "cobalt strike", "sqlmap", "metasploit")


def rule_alert_reasons(log_entry):
    reasons = []
    if log_entry["failed_login_attempts"] >= 10:
        reasons.append("failed_login_attempts")
    if log_entry["bytes_transferred"] >= 100_000_000:
        reasons.append("high_data_volume")
    user_agent = str(log_entry["user_agent"]).lower()
    if any(marker in user_agent for marker in SUSPICIOUS_USER_AGENT_MARKERS):
        reasons.append("suspicious_user_agent")
    return reasons
