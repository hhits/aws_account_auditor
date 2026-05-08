def tag_severity(finding):
    details = finding.get("Details", "").lower()

    if "unrestricted access" in details or "open to the world" in details:
        return "High"
    elif "not enabled" in details or "deprecated" in details:
        return "Medium"
    elif "error" in details or "denied" in details:
        return "Low"
    return "Informational"
