# Microsoft Sentinel Detection & SOAR Engineering

## Overview
This repository is a continuously growing collection of Microsoft Sentinel
detections, KQL queries, and SOAR automations focused on practical detection
engineering and SOC efficiency.

This is a long-term project aimed at building production-minded Sentinel
content and deep expertise in detection and automation.

---

## What’s Included

### Detections (KQL)
- Identity detections (Entra ID / Azure AD)
- Endpoint detections
- Cloud and Azure activity detections
- Behavioral and anomaly-based detections

Each detection will include purpose, KQL logic, MITRE mapping, tuning notes,
and response recommendations.

### SOAR Automations (Logic Apps)
- Alert enrichment playbooks
- Triage and escalation workflows
- Safe containment patterns with approvals

---

## Repository Structure
sentinel-detections/
detections/
identity/
endpoint/
cloud/
network/
playbooks/
enrichment/
triage/
containment/
resources/

---

## Principles
- Signal over noise
- Explainable detections
- Environment-aware logic
- Security-first automation

---

## Disclaimer
Content is provided for educational purposes. Test and adapt before production use.

---

## Roadmap
- Publish foundational KQL queries
- Add MITRE-mapped detections
- Add Logic App playbooks
- Optimize detections for performance and cost
