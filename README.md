# Fortress Threat Defense Platform

🛡️ A comprehensive multi-layer threat defense platform based on OpenClaw kill chain methodology. Implements detection and prevention controls across all stages of the attack lifecycle.

## Overview

Fortress is a production-ready threat defense platform designed to detect and prevent internal system intrusions using a multi-layered approach based on the OpenClaw Ecosystem's cybersecurity kill chain model.

## Kill Chain Defense Stages

### 1. **Reconnaissance** (Detection)
- Skill registry scanning detection
- Suspicious dependency analysis
- Infrastructure probing identification

### 2. **Initial Access** (Prevention)
- Prompt injection detection
- Indirect prompt injection filtering
- Supply chain attack prevention
- Malicious skill package identification

### 3. **Execution** (Containment)
- Credential theft prevention
- Remote code execution blocking
- Unsafe tool usage detection
- Sandbox enforcement

### 4. **Persistence** (Monitoring)
- Data poisoning detection
- Knowledge manipulation tracking
- Memory integrity verification
- Configuration tampering detection

### 5. **Privilege Escalation** (Access Control)
- Unauthorized privilege attempts detection
- Capability scoping enforcement
- Policy engine-based restrictions

### 6. **Impact** (Prevention)
- Data exfiltration blocking
- Network egress control
- Data loss prevention
- Unauthorized action interception

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Fortress Threat Defense Platform               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Threat Detection Engine                       │  │
│  │  - Kill Chain Stage Analyzer                         │  │
│  │  - Pattern Matcher                                   │  │
│  │  - Behavioral Analyzer                              │  │
│  └──────────────────────────────────────────────────────┘  │
│                            │                                 │
│                            ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Multi-Layer Defense Controls                  │  │
│  │  ┌───────────────────┬───────────────────────────┐  │  │
│  │  │  Containment      │  Input Validation         │  │  │
│  │  │  - Sandboxing     │  - Prompt Filtering      │  │  │
│  │  │  - Isolation      │  - Content Filtering     │  │  │
│  │  ├───────────────────┼───────────────────────────┤  │  │
│  │  │  Access Control   │  Supply Chain Controls    │  │  │
│  │  │  - Capability     │  - Dependency Scanning   │  │  │
│  │  │    Scoping        │  - Signature Verification│  │  │
│  │  ├───────────────────┼───────────────────────────┤  │  │
│  │  │  Credential Mgmt  │  Network Protection       │  │  │
│  │  │  - Secrets        │  - Egress Control        │  │  │
│  │  │    Isolation      │  - Data Loss Prevention  │  │  │
│  │  └───────────────────┴───────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                            │                                 │
│                            ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │    Real-Time Monitoring & Response                    │  │
│  │  - Event Logging                                      │  │
│  │  - Alert Generation                                   │  │
│  │  - Incident Response Automation                       │  │
│  │  - Audit Trail                                        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
fortress-threat-defense/
├── fortress_core/           # Core threat detection engine
│   ├── kill_chain/         # Kill chain stage analyzers
│   │   ├── reconnaissance.py
│   │   ├── initial_access.py
│   │   ├── execution.py
│   │   ├── persistence.py
│   │   ├── privilege_escalation.py
│   │   └── impact.py
│   ├── threat_detector.py   # Main threat detection engine
│   ├── threat_rules.py      # Pattern and rule definitions
│   └── __init__.py
├── defense_controls/        # Multi-layer defense controls
│   ├── containment/        # Sandboxing & isolation
│   ├── access_control/     # Capability scoping & policies
│   ├── supply_chain/       # Dependency & package validation
│   ├── credentials/        # Secrets management
│   ├── network_protection/ # Egress & DLP controls
│   └── __init__.py
├── monitoring/             # Real-time monitoring & logging
│   ├── event_logger.py     # Event logging system
│   ├── alert_manager.py    # Alert generation & management
│   ├── metrics.py          # Threat metrics & statistics
│   └── __init__.py
├── api/                   # REST API for threat platform
│   ├── threat_api.py
│   ├── control_api.py
│   ├── monitoring_api.py
│   └── __init__.py
├── config/                # Configuration management
│   ├── threat_rules.json  # Threat detection rules
│   ├── policies.json      # Defense policies
│   └── settings.py        # Platform settings
├── tests/                 # Unit & integration tests
│   ├── test_threat_detection.py
│   ├── test_defense_controls.py
│   └── test_integration.py
├── docker/                # Docker container setup
│   ├── Dockerfile
│   └── docker-compose.yml
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md
│   ├── THREAT_RULES.md
│   ├── DEPLOYMENT.md
│   └── API_REFERENCE.md
├── requirements.txt       # Python dependencies
├── main.py               # Application entry point
└── README.md             # This file
```

## Key Features

### 🔍 Intelligent Threat Detection
- **Kill Chain Mapping**: Identifies threats across all attack lifecycle stages
- **Pattern Matching**: Detects known attack patterns and signatures
- **Behavioral Analysis**: Identifies anomalous system behavior
- **Rule-based Detection**: Customizable threat detection rules

### 🛡️ Multi-Layer Defense Controls
- **Input Validation**: Filters malicious prompts and commands
- **Sandboxing**: Isolates potentially dangerous operations
- **Access Control**: Enforces capability scoping and least privilege
- **Supply Chain Security**: Validates dependencies and packages
- **Network Protection**: Controls data exfiltration
- **Credential Management**: Secure secrets storage and rotation

### 📊 Real-Time Monitoring
- **Event Logging**: Comprehensive audit trail of all security events
- **Alert Generation**: Real-time threat alerts
- **Metrics Dashboard**: Visual threat analytics
- **Incident Tracking**: Track and respond to incidents

### ⚙️ Automation & Response
- **Automated Blocking**: Automatically block detected threats
- **Policy Enforcement**: Enforce security policies
- **Response Orchestration**: Automated incident response workflows

## Installation

### Prerequisites
- Python 3.9+
- Docker & Docker Compose
- Redis (for distributed caching)
- ClickHouse (for analytics)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/eentost/fortress-threat-defense.git
cd fortress-threat-defense

# Install dependencies
pip install -r requirements.txt

# Configure the platform
cp config/settings.example.py config/settings.py

# Run with Docker Compose
docker-compose up -d

# Access the API
curl http://localhost:8000/api/health
```

## Usage

### Detect Threats

```python
from fortress_core.threat_detector import ThreatDetector
from fortress_core.threat_rules import ThreatRules

detector = ThreatDetector()

# Analyze incoming request
threat = detector.analyze_request(
    source="external_api",
    payload=request_payload,
    kill_chain_stage="initial_access"
)

if threat.severity >= "HIGH":
    # Execute defense controls
    detector.trigger_defense(threat)
```

### Apply Defense Controls

```python
from defense_controls.access_control import CapabilityScopingEngine
from defense_controls.network_protection import EgressControl

# Restrict capabilities
scope = CapabilityScopingEngine()
scope.restrict_capabilities(agent_id, allowed_capabilities=[
    "file_read",
    "api_call"
])

# Block unauthorized egress
egress = EgressControl()
egress.block_suspicious_data_exfiltration(
    source_ip="192.168.1.100",
    destination="external_ip",
    data_size=1024*1024
)
```

### Monitor Threats

```python
from monitoring.event_logger import EventLogger
from monitoring.alert_manager import AlertManager

logger = EventLogger()
alerts = AlertManager()

# Log security event
logger.log_event(
    event_type="threat_detected",
    severity="HIGH",
    threat_name="Prompt Injection",
    details={}
)

# Generate alert
alerts.create_alert(
    threat_id=threat.id,
    action_required=True,
    recipients=["security_team@company.com"]
)
```

## Configuration

Edit `config/threat_rules.json` to customize threat detection rules:

```json
{
  "threat_rules": [
    {
      "id": "prompt_injection_001",
      "kill_chain_stage": "initial_access",
      "severity": "CRITICAL",
      "patterns": [
        ".*ignore.*instruction.*",
        ".*system.*override.*"
      ],
      "actions": ["block", "alert"]
    }
  ]
}
```

## API Reference

### GET /api/threats
Retrieve detected threats

### POST /api/threats/analyze
Analyze payload for threats

### POST /api/controls/apply
Apply defense control

### GET /api/monitoring/events
Get security events log

## Testing

```bash
# Run unit tests
pytest tests/test_threat_detection.py

# Run integration tests
pytest tests/test_integration.py

# Run with coverage
pytest --cov=fortress_core tests/
```

## Deployment

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment guide.

### Using Docker

```bash
docker build -t fortress-threat-defense .
docker run -d -p 8000:8000 fortress-threat-defense
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Threat Model Reference

Based on OpenClaw Ecosystem's threat catalog:
- Prompt Injection (CRITICAL)
- Indirect Prompt Injection (CRITICAL)
- Data Poisoning (HIGH)
- Knowledge Manipulation (HIGH)
- Credential Theft (CRITICAL)
- Data Exfiltration (CRITICAL)
- Remote Code Execution (CRITICAL)
- Privilege Escalation (HIGH)
- Supply-chain Attack (CRITICAL)
- User Manipulation (MEDIUM)

See [THREAT_RULES.md](docs/THREAT_RULES.md) for detailed threat descriptions.

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- GitHub Issues: https://github.com/eentost/fortress-threat-defense/issues
- Documentation: https://github.com/eentost/fortress-threat-defense/wiki

## References

- OpenClaw Dashboard: https://hollobit.github.io/clawdash/
- MITRE ATT&CK: https://attack.mitre.org/
- ATLAS ML Security: https://atlas.mitre.org/

---

**Last Updated**: 2026-03-11
**Version**: 1.0.0
