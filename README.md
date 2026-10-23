# QuantumSafe-Checker
### Quantum-Safe Cryptographic Risk Assessment and Migration Planning

**Team:** Wavefunction Warriors  
**Team ID:** VTU-QFF-HC-0136  
**Track:** Quantum Cryptography and Security  
**Institution:** Thiagarajar College of Engineering, Madurai, India  
**Team Leader:** R. Rakchana  
**Team Members:** R. Rakchana, M. S. Sethulatha, K. Rithanyaa

---

## 1. Problem Statement

Quantum computing may threaten widely used public-key cryptographic algorithms, particularly RSA and elliptic-curve cryptography, when sufficiently capable fault-tolerant quantum computers become available. Organizations often lack a centralized view of the cryptographic algorithms used across their systems, making it difficult to identify vulnerable assets and plan migration to post-quantum cryptography (PQC).

QuantumSafe-Checker addresses this challenge by providing a prototype for cryptographic risk assessment, asset inventory analysis, and post-quantum migration planning.

## 2. Proposed Solution

QuantumSafe-Checker helps users assess cryptographic configurations and understand potential quantum-related risks. It provides qualitative risk explanations and migration recommendations for supported algorithm and use-case combinations.

The prototype also supports CSV-based cryptographic asset inventory assessment, enabling users to review multiple assets in a consolidated view.

### Key Features

- **Cryptographic Security Checker:** Assess supported cryptographic algorithms and use cases.
- **Risk Explanations:** Present qualitative findings and explain potential quantum-related vulnerabilities.
- **Migration Recommendations:** Suggest relevant post-quantum cryptographic alternatives for supported configurations.
- **Asset Inventory:** Import a CSV file containing multiple cryptographic assets for assessment.
- **Consolidated Results:** Review algorithm assessments and inventory findings in one interface.
- **Report Export:** Export assessment results for further review and planning.

## 3. System Architecture

The application uses a frontend-backend architecture.

1. **Frontend:** React, TypeScript, and Vite provide the user interface.
2. **Backend API:** Python and FastAPI handle assessment requests and application logic.
3. **Security Rules Engine:** Python-based rules evaluate supported algorithm and use-case combinations.
4. **Algorithm Metadata:** JSON data provides algorithm information used by the assessment engine.
5. **Inventory and Reporting:** Python modules process asset inventory data and prepare assessment reports.

### Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI, Uvicorn |
| Validation | Pydantic |
| Data Processing | Pandas |
| Configuration | JSON |
| Version Control | Git and GitHub |

## 4. How It Works

1. The user selects a cryptographic algorithm and its intended use case.
2. The frontend sends the assessment request to the backend API.
3. The rules engine evaluates the supported configuration.
4. The application displays the qualitative risk assessment and relevant migration guidance.
5. Alternatively, the user uploads a CSV cryptographic asset inventory to assess multiple entries.
6. The user reviews the results and exports the report when needed.

## 5. Installation and Setup

### Prerequisites

- Python 3.10 or later
- Node.js and npm
- Git

### Clone the Repository

```bash
git clone https://github.com/vtu-qiskit-fall-fest-2026/vtu-hc-wavefunction-warriors.git
cd vtu-hc-wavefunction-warriors
```

### Backend Setup

From the repository root:

```bash
python -m venv .venv
```

Activate the virtual environment on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the backend:

```bash
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8003
```

The backend will be available at:

`http://127.0.0.1:8003`

API health endpoint:

`http://127.0.0.1:8003/api/health`

### Frontend Setup

Open a second terminal:

```bash
cd frontend
npm install
```

Create a local `.env` file in the `frontend` directory with:

```env
VITE_API_BASE_URL=http://127.0.0.1:8003
```

Start the frontend:

```bash
npm run dev -- --port 5174
```

Open the application at:

`http://localhost:5174`

Keep both the backend and frontend running while using the application.

## 6. Example Use Cases

- Reviewing RSA-based key establishment configurations.
- Assessing supported digital-signature configurations.
- Identifying cryptographic assets that may require post-quantum migration planning.
- Importing a CSV inventory to consolidate cryptographic assessment results.
- Exploring post-quantum alternatives such as ML-KEM and ML-DSA where applicable.

Recommendations depend on the algorithm, use case, and implementation context. They should be reviewed by qualified security professionals before production adoption.

## 7. Limitations

QuantumSafe-Checker is a hackathon prototype intended to support cryptographic awareness and migration planning.

- Assessments depend on the implemented rules and available algorithm metadata.
- Results are qualitative prototype assessments, not a comprehensive security audit.
- Inventory results depend on the accuracy and completeness of the supplied data.
- Migration recommendations require review against application requirements, protocol support, interoperability, and applicable standards.
- The current implementation uses classical software-based rules and does not execute quantum circuits or demonstrate quantum speedup.

The tool should not be treated as a replacement for a professional cryptographic audit or production security validation.

## 8. Future Scope

- Expand algorithm and protocol coverage.
- Improve risk scoring and asset prioritization.
- Enhance cryptographic discovery and inventory integration.
- Add richer migration planning and progress tracking.
- Improve report generation and standards-reference mapping.
- Integrate with enterprise security and asset-management workflows.

## 9. Demo and Resources

- **GitHub Repository:** https://github.com/vtu-qiskit-fall-fest-2026/vtu-hc-wavefunction-warriors
- **Demo Video:** [Add the YouTube demo URL here]
- **Presentation:** [Add the presentation link if required]

## 10. Acknowledgement

Developed by **Wavefunction Warriors** for **Qiskit Fall Fest 2026**, under the Quantum Cryptography and Security track.

Our goal is to make quantum-related cryptographic risks easier to understand and help organizations begin planning their transition toward post-quantum cryptography.
