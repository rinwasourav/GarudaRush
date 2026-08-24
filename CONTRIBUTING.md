# Contributing to GarudaRush

Thank you for considering contributing to **GarudaRush**! We welcome contributions from developers, researchers, and security analysts.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs
Before opening a new bug report, search existing issues to see if it has already been reported.
When filing a bug, please use the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md) and include:
- Operating system and Python version
- Steps to reproduce
- Relevant log output or tracebacks

### Requesting Features
Feature suggestions are welcome! Use the [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md) to outline:
- The problem your feature solves
- Proposed design or API interface
- Any alternative approaches considered

### Submitting Pull Requests

1. **Fork the Repository**: Create your own fork of `rinwasourav/GarudaRush`.
2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Set Up Development Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
4. **Make Changes & Add Tests**:
   - Ensure all code is cleanly formatted and typed where possible.
   - Add unit tests for new functionality in `tests/test_suite.py`.
5. **Run Test Suite**:
   ```bash
   python3 -m unittest discover -s tests -p "test_suite.py"
   ```
6. **Commit & Push**:
   ```bash
   git commit -m "feat(agent): add support for custom flow window intervals"
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**: Submit your PR targeting the `main` branch with a description of changes.

## Development Guidelines

- Follow PEP-8 Python coding conventions.
- Keep dependencies minimal and documented in `requirements.txt`.
- Do not commit dataset CSV files or binary artifacts over 50MB.
