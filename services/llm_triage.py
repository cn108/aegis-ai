import os
import json
import logging

from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Aegis, an expert Tier-3 Cybersecurity Analyst. I will
provide you with a raw network log flagged as an anomaly. Your job is to: 1. Identify the
likely MITRE ATT&CK tactic (e.g. Initial Access, Exfiltration). 2. Assess the severity (Low,
Medium, High, CRITICAL). 3. Write a 2-sentence plain English summary for a junior analyst. 4.
Provide 3 actionable remediation steps. Respond ONLY in valid JSON matching this schema:
{"tactic": "", "severity": "", "summary": "", "remediation": []}"""

class LLMTriageService:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        if self.api_key and self.api_key != "your_api_key_here":
            self.client = OpenAI(api_key=self.api_key)
        else:
            self.client = None

    def triage_anomaly(self, log_entry):
        if not self.client:
            return self._mock_triage(log_entry)

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this network log: {json.dumps(log_entry)}"}
                ],
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content
            if not content:
                raise ValueError("The triage provider returned an empty response.")
            result = json.loads(content)
            self._validate_result(result)
            return result
        except Exception as exc:
            logger.exception("LLM triage request failed")
            raise RuntimeError("LLM triage request failed.") from exc

    @staticmethod
    def _validate_result(result):
        if not isinstance(result, dict):
            raise ValueError("The triage response must be a JSON object.")
        if set(result) != {"tactic", "severity", "summary", "remediation"}:
            raise ValueError("The triage response does not match the required schema.")
        if not isinstance(result["tactic"], str) or not result["tactic"].strip():
            raise ValueError("The triage response must include a tactic.")
        if not isinstance(result["severity"], str):
            raise ValueError("The triage response contains an invalid severity.")
        severity = result["severity"].upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("The triage response contains an invalid severity.")
        result["severity"] = severity
        if not isinstance(result["summary"], str) or not result["summary"].strip():
            raise ValueError("The triage response must include a summary.")
        if (
            not isinstance(result["remediation"], list)
            or len(result["remediation"]) != 3
            or not all(isinstance(step, str) and step.strip() for step in result["remediation"])
        ):
            raise ValueError("The triage response must include exactly three remediation steps.")

    def _mock_triage(self, log_entry):
        # Fallback/Mock logic for development without API key
        dest_port = log_entry.get("dest_port")
        bytes_transferred = log_entry.get("bytes_transferred", 0)

        if dest_port in [22, 3389]:
            return {
                "tactic": "Initial Access (Brute Force)",
                "severity": "HIGH",
                "summary": f"Detected suspicious login attempts on port {dest_port} from {log_entry.get('source_ip')}. This suggests an active brute-force attempt targeting remote access services.",
                "remediation": [
                    "Block source IP at the edge firewall.",
                    "Audit login logs for the target system.",
                    "Enforce multi-factor authentication (MFA)."
                ]
            }
        elif bytes_transferred > 1000000:
            return {
                "tactic": "Exfiltration",
                "severity": "CRITICAL",
                "summary": f"Massive data transfer ({bytes_transferred} bytes) detected from {log_entry.get('source_ip')} to {log_entry.get('dest_ip')}. This may indicate a data breach or unauthorized backup.",
                "remediation": [
                    "Terminate the active session immediately.",
                    "Isolate the source and destination hosts.",
                    "Verify the nature of the transferred data."
                ]
            }
        else:
            return {
                "tactic": "Persistence / Command & Control",
                "severity": "MEDIUM",
                "summary": "Detected unusual network activity with suspicious metadata. The pattern aligns with potential beaconing or persistence mechanisms.",
                "remediation": [
                    "Scan the host for unauthorized agents.",
                    "Check for scheduled tasks or unusual startup items.",
                    "Monitor outbound traffic for further signals."
                ]
            }

if __name__ == "__main__":
    # Test
    service = LLMTriageService()
    test_log = {
        "timestamp": "2026-10-09T14:32:01Z",
        "source_ip": "45.22.11.90",
        "dest_ip": "10.0.4.15",
        "dest_port": 22,
        "protocol": "TCP",
        "bytes_transferred": 1054300,
        "failed_login_attempts": 12,
        "user_agent": "Nmap Scripting Engine",
        "geo_location": "RU"
    }
    print(json.dumps(service.triage_anomaly(test_log), indent=2))
