
# ⚙️ StellarFlow Backend (`stellarflow-backend`)

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python Version](https://img.shields.io/badge/Python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.100+-green.svg)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)
![Coverage](https://img.shields.io/badge/Coverage-90%25+-blue.svg)

> High-performance microservice architecture, off-chain event ingestion, transaction relayer engine, and REST/WebSocket API gateways powering **StellarFlow**—the next-generation DEX, yield, and cross-border remittance protocol on the Stellar network.

---

## 🏛️ Architecture & System Overview

`stellarflow-backend` handles off-chain processing, indexing, transaction relaying, and liquidity aggregation for the StellarFlow ecosystem. Built with FastAPI, PostgreSQL/TimescaleDB, and Redis, the backend provides low-latency data pipelines and seamless integration with Soroban smart contracts and Stellar SEP protocols.

```text
stellarflow-backend/
├── app/
│   ├── api/          # REST & WebSocket API route handlers (FastAPI)
│   ├── auth/         # SEP-10 JWT auth, OAuth2/OIDC, and WebAuthn handlers
│   ├── core/         # Settings, logging, Database connections, & Redis pools
│   ├── indexer/      # Soroban RPC event stream parsers & XDR deserializer
│   ├── models/       # AsyncPG/SQLAlchemy ORM schemas & Pydantic models
│   ├── relayer/      # Relayer wallet sequence guards & KMS transaction signers
│   ├── remittance/   # SEP-12 (KYC), SEP-24 (Interactive), & SEP-31/38 quote servers
│   ├── services/     # Order book matching, TWAP pricing, & liquidity route solvers
│   └── workers/      # Celery background jobs, liquidation triggers, & auto-harvesters
├── migrations/       # Alembic database schema migrations
├── scripts/          # Developer tooling, database seeders, & setup scripts
└── tests/            # Pytest unit, integration, & Locust load testing suites

```

---

## 🛠 Tech Stack & Services

* **Framework:** Python 3.11+ / FastAPI
* **Database & Caching:** PostgreSQL 15+ (AsyncPG) / TimescaleDB & Redis Sentinel
* **Task Queue & Event Bus:** Celery & Redis Streams
* **Blockchain Integration:** Soroban RPC, Stellar SDK, XDR Parsers
* **Authentication & Security:** SEP-10, WebAuthn, AWS KMS, OAuth2
* **Monitoring & Observability:** Prometheus, Grafana, OpenTelemetry, & Sentry

---

## 🚀 Quickstart Guide

### Prerequisites

* Docker & Docker Compose
* Python 3.11+
* Poetry or `pip`

### 1. Local Environment Setup

Clone the repository and install dependencies:

```bash
git clone [https://github.com/stellarflow/stellarflow-backend.git](https://github.com/stellarflow/stellarflow-backend.git)
cd stellarflow-backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

### 2. Infrastructure Setup (Docker)

Spin up PostgreSQL, Redis, and local Soroban RPC containers:

```bash
docker-compose up -d

```

### 3. Database Migrations & Seeding

Apply database migrations and populate staging mock data:

```bash
alembic upgrade head
python -m app.cli seed-db

```

### 4. Running the API Gateway

Start the FastAPI development server with hot-reloading:

```bash
uvicorn app.main:app --reload --port 8000

```

Visit `http://localhost:8000/docs` to access interactive Swagger API documentation.

---

## 🧪 Testing & Code Quality

Run unit and integration test suites with Pytest:

```bash
# Run all tests with coverage report
pytest --cov=app --cov-report=term-missing

# Run end-to-end integration tests
pytest tests/e2e/

```

Run linter and code formatting checks:

```bash
black --check app/
ruff check app/
mypy app/

```


---

## 🤝 Contributing

We welcome open-source contributions! Please pick any open task from the issue tracker labeled `good-first-issue` or `help-wanted`.

1. **Fork the repo** and create a feature branch (`git checkout -b feature/my-feature`).
2. **Commit your changes** and add unit test coverage.
3. **Submit a Pull Request** linking the issue ID.

*Thank you for contributing to the StellarFlow backend infrastructure!*

---

## 📄 License

This repository is licensed under the [MIT License](https://www.google.com/search?q=LICENSE).

```

```
