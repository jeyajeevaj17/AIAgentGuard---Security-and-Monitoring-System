# AgentGuard – AI Agent Security & Permission Management Platform

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-JWT-blue.svg)](https://spring.io/projects/spring-security)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-blue.svg)](https://www.mysql.com/)
[![React](https://img.shields.io/badge/React-18-cyan.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5.4-purple.svg)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](LICENSE)

---

## 1. Executive Summary & Problem Statement

As autonomous AI agents (LLM agents, coding assistants, financial processors, DevOps bots) become ubiquitous across enterprise architectures, organizations face critical security vulnerabilities:
* **Overprivileged Access**: Agents granted blanket credentials or database connectivity with no operational boundaries.
* **Non-Deterministic Threat Surface**: Destructive actions (e.g., `DELETE`, `EXPORT`) requested on restricted repositories and production databases.
* **Lack of Attribution & Auditing**: No immutable record connecting which agent executed what action, why, and what risk level was present at evaluation time.

**AgentGuard** solves this by establishing a **Zero-Trust Governance Perimeter** over AI agents. Every agent action is intercepted, evaluated against explicit granular permissions, scored through a multi-factor deterministic risk engine, vetted against real-time anomaly detection rules, and logged to an immutable audit ledger.

---

## 2. Core Capabilities

* **AI Agent Registry**: Full lifecycle governance, status tracking (`ACTIVE`, `INACTIVE`, `SUSPENDED`), and baseline risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **Protected Resource Catalog**: Asset classification across databases, APIs, code repositories, document stores, and cloud services with sensitivity labels (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
* **Zero-Trust Permission Engine**: Explicit mapping of `Agent → Protected Resource → Operation` (`READ`, `WRITE`, `UPDATE`, `DELETE`, `EXECUTE`, `EXPORT`). Enforces composite uniqueness preventing policy collisions.
* **Deterministic Risk Assessment Engine (0–100)**: Multi-parameter mathematical scoring incorporating agent baseline multiplier, resource sensitivity points, operation danger factors, historical denial rates, and permission compliance.
* **Automated Anomaly Detection Engine**: Rule-based detection capturing:
  1. *Dangerous operations on restricted resources* (immediate CRITICAL incident).
  2. *Repeated consecutive access denials* (>= 3 rejections).
  3. *Unusual request volume rate spikes* (> 20 requests/hour).
  4. *Unauthorized sensitive asset probes*.
* **Incident Triage & Security Event Management**: Security incident lifecycle (`OPEN` → `INVESTIGATING` → `RESOLVED`) with forensic investigation notes.
* **Immutable Security Audit Ledger**: Historical tamper-evident logs tracking every access request, evaluation decision, permission change, and resolution.
* **Enterprise Role-Based Access Control (RBAC)**: Fine-grained method-level security (`ROLE_ADMIN`, `ROLE_SECURITY_ANALYST`, `ROLE_DEVELOPER`, `ROLE_VIEWER`).
* **Cybersecurity Operations Dashboard**: Real-time KPI telemetry, Recharts risk score distribution donut charts, access decision bar charts, and live incident feeds.

---

## 3. High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                   AgentGuard Platform Architecture                     │
└────────────────────────────────────────────────────────────────────────┘

    React 18 SPA (Vite + Recharts)          Swagger / OpenAPI 3.0 UI
         │                                            │
         └──────────────────────┬─────────────────────┘
                                │ HTTP / REST (JWT Bearer)
                                ▼
    ┌────────────────────────────────────────────────────────────┐
    │              Spring Boot 3.3.4 Security Layer              │
    │  - CorsConfig           - JwtAuthenticationFilter          │
    │  - SecurityConfig       - JwtAuthenticationEntryPoint      │
    │  - BCrypt Hashing       - Method-Level RBAC (@PreAuthorize)│
    └───────────────────────────┬────────────────────────────────┘
                                │
                                ▼
    ┌────────────────────────────────────────────────────────────┐
    │                      REST Controllers                      │
    │  /api/auth       /api/users            /api/agents         │
    │  /api/resources  /api/permissions      /api/access-requests│
    │  /api/dashboard  /api/security-events  /api/audit-logs     │
    └───────────────────────────┬────────────────────────────────┘
                                │
    ┌───────────────────────────┴────────────────────────────────┐
    │                     Service Core Layer                     │
    │  ┌───────────────────────┐    ┌─────────────────────────┐  │
    │  │   PermissionService   │    │  RiskAssessmentService  │  │
    │  └───────────┬───────────┘    └────────────┬────────────┘  │
    │              │                             │               │
    │              ▼                             ▼               │
    │  ┌───────────────────────┐    ┌─────────────────────────┐  │
    │  │  AccessRequestService │───▶│ AnomalyDetectionService │  │
    │  └───────────┬───────────┘    └────────────┬────────────┘  │
    │              │                             │               │
    │              ▼                             ▼               │
    │  ┌───────────────────────┐    ┌─────────────────────────┐  │
    │  │    AuditLogService    │    │   SecurityEventService  │  │
    │  └───────────────────────┘    └─────────────────────────┘  │
    └───────────────────────────┬────────────────────────────────┘
                                │ Spring Data JPA / Hibernate
                                ▼
    ┌────────────────────────────────────────────────────────────┐
    │                      MySQL 8.0 Relational                  │
    │  users | roles | agents | resources | permissions          │
    │  access_requests | security_events | audit_logs            │
    └────────────────────────────────────────────────────────────┘
```

---

## 4. Deterministic Risk Assessment Formula

The **Risk Assessment Engine** evaluates incoming requests using a deterministic mathematical model:

$$\text{RawScore} = \left( \frac{\text{SensitivityBase} \times \text{AgentMultiplier} \times \text{OperationMultiplier}}{374.0} \right) \times 70.0 + \text{DenialPenalty} + \text{PermissionPenalty}$$

### Parameter Weights:
1. **Resource Sensitivity Base**:
   - `PUBLIC`: 10 pts
   - `INTERNAL`: 30 pts
   - `CONFIDENTIAL`: 60 pts
   - `RESTRICTED`: 85 pts
2. **Agent Risk Multiplier**:
   - `LOW`: 1.0x
   - `MEDIUM`: 1.3x
   - `HIGH`: 1.7x
   - `CRITICAL`: 2.2x
3. **Operation Danger Multiplier**:
   - `READ`: 1.0x
   - `EXECUTE`: 1.3x
   - `WRITE`, `UPDATE`: 1.5x
   - `EXPORT`: 1.8x
   - `DELETE`: 2.0x
4. **Denial & Anomaly Penalty**:
   - `DenialPenalty` = $\min(20, \text{RecentDenials} \times 5)$
   - `PermissionPenalty` = $+15$ if explicit authorization rule is absent.

### Output Normalized Scale (0–100):
- **0 – 34**: `LOW` Risk
- **35 – 59**: `MEDIUM` Risk
- **60 – 84**: `HIGH` Risk
- **85 – 100**: `CRITICAL` Risk (Automatically triggers `BLOCKED` policy)

---

## 5. Technology Stack

### Backend
- **Language**: Java 21 LTS (OpenJDK 21)
- **Framework**: Spring Boot 3.3.4
- **Security**: Spring Security 6, JJWT 0.12.5 (HMAC-SHA256), BCrypt
- **ORM & Data**: Spring Data JPA, Hibernate ORM
- **Database**: MySQL 8.0 Community Server
- **API Specs**: SpringDoc OpenAPI 2.5.0 / Swagger UI 3.0
- **Utilities**: Project Lombok, Jakarta Bean Validation

### Frontend
- **Framework**: React 18
- **Tooling**: Vite 5.4
- **Routing**: React Router DOM 6.26
- **HTTP Client**: Axios 1.7 (with Bearer Interceptors & Structured Error Handling)
- **Analytics & Charts**: Recharts 2.12
- **Icons**: Lucide React
- **Design System**: Vanilla CSS3 Custom Properties (Dark Cybersecurity Theme)

---

## 6. Database Schema Design

The MySQL schema is normalized and indexed for high-throughput query performance:

| Table | Primary Key | Key Foreign Keys & Constraints |
|---|---|---|
| `roles` | `id` | `name` (UNIQUE ENUM) |
| `users` | `id` | `email` (UNIQUE), FK `role_id` -> `roles(id)` |
| `agents` | `id` | `name` (UNIQUE), Indexed: `status`, `risk_level` |
| `resources` | `id` | `name` (UNIQUE), Indexed: `resource_type`, `sensitivity_level` |
| `permissions` | `id` | `UNIQUE(agent_id, resource_id, permission_type)` |
| `access_requests` | `id` | FK `agent_id`, FK `resource_id`, FK `requested_by` |
| `security_events` | `id` | FK `agent_id`, FK `resolved_by` -> `users(id)` |
| `audit_logs` | `id` | FK `user_id`, FK `agent_id`, FK `resource_id` |

---

## 7. REST API Reference

### Authentication
- `POST /api/auth/login`: Authenticate credentials & receive JWT token.
- `GET /api/auth/me`: Get current authenticated user profile (`Bearer <JWT>`).

### User Management (`ROLE_ADMIN`, `ROLE_SECURITY_ANALYST`)
- `GET /api/users`: Search and filter users by role and status.
- `GET /api/users/{id}`: User profile by ID.
- `POST /api/users`: Create operator account.
- `PUT /api/users/{id}`: Modify user attributes.
- `DELETE /api/users/{id}`: Safe deactivation / delete.

### AI Agent Governance
- `GET /api/agents`: Catalog of registered AI agents.
- `GET /api/agents/{id}`: Agent dossier.
- `POST /api/agents`: Register new AI agent.
- `PUT /api/agents/{id}`: Update agent parameters.
- `DELETE /api/agents/{id}`: Deactivate/suspend agent.

### Protected Resources
- `GET /api/resources`: Catalog of protected enterprise assets.
- `GET /api/resources/{id}`: Resource specification.
- `POST /api/resources`: Register protected asset.
- `PUT /api/resources/{id}`: Update resource attributes.
- `DELETE /api/resources/{id}`: Deactivate resource.

### Permission Engine
- `GET /api/permissions`: List active permission mappings.
- `GET /api/permissions/agent/{agentId}`: Permissions granted to agent.
- `GET /api/permissions/resource/{resourceId}`: Rules protecting resource.
- `POST /api/permissions`: Grant permission rule.
- `DELETE /api/permissions/{id}`: Revoke permission rule.

### Access Request & Decision Engine
- `GET /api/access-requests`: Filterable history of access requests.
- `GET /api/access-requests/{id}`: Request details and risk rationale.
- `POST /api/access-requests`: Submit agent access request for automated evaluation.
- `POST /api/access-requests/{id}/approve`: Manually approve request.
- `POST /api/access-requests/{id}/deny`: Manually deny request.

### Security Incident Management
- `GET /api/security-events`: Filterable security incidents.
- `GET /api/security-events/{id}`: Incident details.
- `POST /api/security-events/{id}/investigate`: Mark incident under investigation.
- `POST /api/security-events/{id}/resolve`: Resolve incident with remediation notes.

### Audit Logging
- `GET /api/audit-logs`: Immutable historical audit records with multi-attribute filtering.

### Dashboard & Analytics
- `GET /api/dashboard/summary`: High-level security KPIs and totals.
- `GET /api/dashboard/activity`: Recent access requests and incident feeds.
- `GET /api/dashboard/risk-distribution`: Risk level distribution for Recharts.
- `GET /api/dashboard/access-summary`: Decision counts (`APPROVED`, `DENIED`, `BLOCKED`, `PENDING`).

---

## 8. Demo Credentials & Test Users

The application seeds realistic demo users with pre-configured BCrypt hashes upon first launch:

| Role | Email | Password | Access Scope |
|---|---|---|---|
| **Admin** | `admin@agentguard.com` | `Admin@123` | Full governance, user creation, rule management |
| **Security Analyst** | `analyst@agentguard.com` | `Analyst@123` | Incident triaging, resolution, audit inspection |
| **Developer** | `developer@agentguard.com` | `Dev@12345` | Agent registration, access request submission |
| **Viewer** | `viewer@agentguard.com` | `Viewer@123` | Read-only telemetry, dashboards, and reports |

---

## 9. Installation & Getting Started

### Prerequisites
- Java 21 JDK or higher
- Node.js v18+ and npm
- MySQL Server 8.0 running locally on port 3306

### Step 1: Database Setup
Connect to MySQL and create the database (or allow Spring Boot to auto-create):
```sql
CREATE DATABASE IF NOT EXISTS agentguard_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Step 2: Run the Backend
Navigate to the `backend/` directory:
```bash
cd backend
.\mvnw.cmd spring-boot:run
```
The backend starts on `http://localhost:8080`.
- Health Endpoint: `http://localhost:8080/api/health`
- Swagger UI Documentation: `http://localhost:8080/swagger-ui.html`
- OpenAPI Specification: `http://localhost:8080/v3/api-docs`

### Step 3: Run the Frontend
In a separate terminal, navigate to the `frontend/` directory:
```bash
cd frontend
npm install
npm run dev
```
The React application will be available at `http://localhost:5173`.

---

## 10. End-to-End Walkthrough Scenarios

### Scenario A: Authorized Low-Risk Request
1. Log in as **Developer** (`developer@agentguard.com`).
2. Navigate to **Access Requests** and click **Submit Access Request**.
3. Select `CodeReviewAgent`, resource `GitHub Repository`, action `READ`.
4. Submit:
   - Permission rule exists in database.
   - Evaluated Risk: `LOW` (Score: 6/100).
   - Automated Decision: **`APPROVED`**.

### Scenario B: Unauthorized High-Risk Destructive Attempt (Blocked Threat)
1. Navigate to **Access Requests** and click **Submit Access Request**.
2. Select `FinanceBot`, resource `Payroll Database`, action `DELETE`.
3. Reason: "Purge fiscal records".
4. Submit:
   - Resource is `RESTRICTED` sensitivity.
   - Action is destructive (`DELETE` 2.0x multiplier).
   - No explicit permission exists (+15 penalty).
   - Evaluated Risk: `CRITICAL` (Score: 94/100).
   - Automated Decision: **`BLOCKED`**.
   - Anomaly Engine automatically triggers a **`DANGEROUS_RESTRICTED_OPERATION`** security incident with CRITICAL severity.
5. Log in as **Security Analyst** (`analyst@agentguard.com`).
6. Navigate to **Security Events**, view the new critical alert, click **Triage** and **Resolve** with forensic notes.

---

## 11. Future AI / LLM Integration Readiness

AgentGuard is architected with modular interfaces ready for external LLM plug-in:
- **`RiskAssessmentService`**: Clean separation of statistical risk factors allowing an LLM to generate contextual natural language threat rationales.
- **`AnomalyDetectionService`**: Extensible for vector-based semantic anomaly detection over agent prompt histories.
- **Natural Language Governance**: Ready for LLM policy query translation into database permission rules.

---

## 12. License & Author

Developed by the **AgentGuard Engineering Team** as an enterprise-grade security reference implementation for AI Agent Governance, Zero-Trust Access Control, and Autonomous Monitoring.
Released under the Apache 2.0 License.
