# Contributing to DeepFence

Thank you for considering a contribution to DeepFence. This project is an
experimental AI-based IDS/IPS pipeline that connects Suricata event collection,
machine learning inference, policy scoring, blocking, and event storage.

## Good First Contribution Areas

- Improve documentation and setup instructions
- Add or refine tests for `service/common`, `service/sensor`, and
  `service/blocker`
- Improve Suricata event to model feature mapping
- Add HTTP, DNS, TLS, or flow-based detection signatures
- Improve policy thresholds and false-positive handling
- Add OpenSearch dashboards or example queries
- Document model evaluation results and known limitations

## Development Setup

```bash
git clone https://github.com/<your-github-username>/DeepFence.git
cd DeepFence
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest
cp service/configs/.env.example service/configs/.env
```

## Running Tests

```bash
python -m pytest service/tests
```

If your change touches model features, policy scoring, or blocking behavior,
please add or update focused tests where possible.

## Pull Request Guidelines

- Keep changes focused and explain the motivation clearly.
- Include reproduction steps for bug fixes.
- Document behavior changes in `README.md` or `docs/` when relevant.
- Avoid committing private datasets, secrets, local `.env` files, or large
  generated artifacts.
- For security-sensitive changes, describe the risk and mitigation clearly.

## Responsible Security Work

DeepFence is intended for defensive security research and authorized network
monitoring. Contributions that enable unauthorized access, stealth, exploitation,
or abuse are not appropriate for this project.

When adding detection or blocking logic, prefer explainable behavior, clear
metadata, and conservative defaults.
