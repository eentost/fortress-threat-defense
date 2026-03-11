"""Threat Detection Engine Implementation

Main threat detector for analyzing payloads against kill chain stages.
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import hashlib


class Severity(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class KillChainStage(Enum):
    """OpenClaw kill chain stages"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    IMPACT = "impact"


@dataclass
class Threat:
    """Represents a detected threat"""
    id: str
    name: str
    description: str
    severity: Severity
    kill_chain_stage: KillChainStage
    detected_patterns: List[str]
    timestamp: str
    source: str
    payload_hash: str
    confidence: float
    mitigations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['severity'] = self.severity.value
        result['kill_chain_stage'] = self.kill_chain_stage.value
        return result


class ThreatDetector:
    """Main threat detection engine"""

    def __init__(self):
        """Initialize the detector"""
        self.detected_threats: List[Threat] = []
        self.threat_counter = 0
        self.load_detection_rules()

    def load_detection_rules(self) -> None:
        """Load threat detection rules"""
        self.rules = {
            KillChainStage.INITIAL_ACCESS: [
                {
                    'name': 'Prompt Injection',
                    'patterns': [
                        r'ignore\s+(previous|instructions|guidelines)',
                        r'system\s+(override|bypass|admin)',
                        r'disregard.*security',
                    ],
                    'severity': Severity.CRITICAL,
                    'mitigations': ['Input Validation', 'Prompt Filtering']
                },
                {
                    'name': 'Indirect Prompt Injection',
                    'patterns': [
                        r'<script[^>]*>.*?</script>',
                        r'javascript:',
                        r'data:text/html',
                    ],
                    'severity': Severity.CRITICAL,
                    'mitigations': ['Content Filtering', 'Sandboxing']
                }
            ],
            KillChainStage.EXECUTION: [
                {
                    'name': 'Remote Code Execution',
                    'patterns': [
                        r'__import__\(',
                        r'eval\(',
                        r'exec\(',
                        r'subprocess\.',
                    ],
                    'severity': Severity.CRITICAL,
                    'mitigations': ['Capability Scoping', 'Sandboxing']
                }
            ],
            KillChainStage.PERSISTENCE: [
                {
                    'name': 'Data Poisoning',
                    'patterns': [
                        r'DROP\s+TABLE',
                        r'DELETE\s+FROM',
                        r'UPDATE.*SET',
                    ],
                    'severity': Severity.HIGH,
                    'mitigations': ['Memory Integrity Checks', 'Data Validation']
                }
            ]
        }

    def analyze_request(
        self,
        payload: str,
        source: str = "unknown",
        kill_chain_stage: Optional[KillChainStage] = None
    ) -> Optional[Threat]:
        """Analyze a request for threats"""
        if not payload:
            return None

        stages_to_check = [kill_chain_stage] if kill_chain_stage else KillChainStage

        for stage in stages_to_check:
            if stage not in self.rules:
                continue

            for rule in self.rules[stage]:
                detected_patterns = self._match_patterns(payload, rule['patterns'])
                if detected_patterns:
                    threat = self._create_threat(
                        name=rule['name'],
                        severity=rule['severity'],
                        stage=stage,
                        source=source,
                        payload=payload,
                        patterns=detected_patterns,
                        mitigations=rule['mitigations']
                    )
                    self.detected_threats.append(threat)
                    return threat

        return None

    def _match_patterns(self, payload: str, patterns: List[str]) -> List[str]:
        """Match patterns against payload"""
        matched = []
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                matched.append(pattern)
        return matched

    def _create_threat(
        self,
        name: str,
        severity: Severity,
        stage: KillChainStage,
        source: str,
        payload: str,
        patterns: List[str],
        mitigations: List[str]
    ) -> Threat:
        """Create a threat object"""
        self.threat_counter += 1
        threat_id = f"THR-{self.threat_counter:06d}"
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]

        return Threat(
            id=threat_id,
            name=name,
            description=f"Threat detected: {name}",
            severity=severity,
            kill_chain_stage=stage,
            detected_patterns=patterns,
            timestamp=datetime.utcnow().isoformat(),
            source=source,
            payload_hash=payload_hash,
            confidence=0.95,
            mitigations=mitigations
        )

    def get_threats(self) -> List[Dict[str, Any]]:
        """Get all detected threats"""
        return [threat.to_dict() for threat in self.detected_threats]

    def clear_threats(self) -> None:
        """Clear threat log"""
        self.detected_threats = []
