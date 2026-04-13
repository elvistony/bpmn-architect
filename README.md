<div align="center">
  <img src="https://img.icons8.com/?size=96&id=Z5oVE4Bv4Ws5&format=png" alt="BPMN Architect Logo" width="120" />

  <h1>BPMN Architect</h1>
  <p><strong>Collaborative Process Mapping & Self-Hosted Live BPMN Editor</strong></p>

  <p>
    <img src="https://img.shields.io/github/stars/your-org/bpmn-architect?style=for-the-badge&color=gold" alt="Stars" />
    <img src="https://img.shields.io/github/forks/your-org/bpmn-architect?style=for-the-badge&color=blue" alt="Forks" />
    <img src="https://img.shields.io/github/issues/your-org/bpmn-architect?style=for-the-badge&color=red" alt="Issues" />
    <img src="https://img.shields.io/badge/Python-3.11+-blue.svg?style=for-the-badge&logo=python" alt="Python 3.11+" />
    <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi" alt="FastAPI" />
  </p>
</div>

---

## Overview

**BPMN Architect** is a robust, lightweight, self-hosted Live BPMN Editor tailored for secure, real-time enterprise process modeling. Designed with a priority on data integrity, it uses local storage for `.bpmn` XML payloads and a centralized SQLite database for high-performance lock management and metadata handling.

This platform bridges the gap between sophisticated BPMN modeling via `bpmn.io` and zero-collision collaboration, ensuring a consistent and friction-free process mapping experience for your organization.

![Dashboard Preview](/docs/img/dashboard_preview.png)

## Key Highlights

- 🔒 **Collision-Free Collaboration:** Heartbeat-based file locking ensures only one user edits a process at a time.
- 🎨 **Modern Interface:** A clean, responsive UI with a built-in Library, centralized Admin portal, and specialized embed modes.
- 🏢 **Enterprise Ready:** Architected to run securely behind Microsoft IIS with full Windows Authentication (Active Directory) support.
- 💾 **Decoupled Architecture:** Native integration for an overnight "cold backup" script connecting automatically to your Git repository.

## Documentation Reference

Dive into our comprehensive documentation to start modeling today:

- 🚀 [**Getting Started & Deployment**](docs/DEPLOYMENT.md) - Host the application using Uvicorn and IIS.
- ⚙️ [**Configuration Guide**](docs/CONFIGURATION.md) - Master the nested `config.yaml` file.
- ✨ [**Platform Features**](docs/FEATURES.md) - Deep dive into locking, embeddings, and Admin controls.
- 📝 [**Notes & Future Goals**](docs/NOTES_AND_GOALS.md) - Architectural decisions and the development roadmap.
- 🤝 [**Contributing Guidelines**](docs/CONTRIBUTING.md) - Guidelines for branching and submitting PRs.

---
<div align="center">
  <i>Built to make process automation accessible for every department.</i>
</div>
