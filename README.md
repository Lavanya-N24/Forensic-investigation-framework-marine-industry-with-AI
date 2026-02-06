# Digital Forensic Investigation Framework for Marine Industry

## Project Overview
This project is an **AI-powered Digital Forensic Investigation Framework** designed to detect anomalies in marine navigation systems. It leverages **Python** and **Machine Learning** for anomaly detection (such as GPS spoofing) and integrates **Blockchain technology** to ensure secure, tamper-proof storage of digital evidence.

## Key Features
- **Real-time Anomaly Detection**: Uses AI to detect irregularities in marine navigation data (e.g., GPS spoofing, suspicious login attempts).
- **Blockchain Evidence Locker**: Securely stores hash values of digital evidence on a private blockchain to prevent tampering.
- **Forensics Dashboard**: Interactive dashboard for visualizing anomalies and managing evidence.
- **Admin & Officer Interfaces**: Dedicated portals for reporting and verifying incidents.

## Technology Stack

### Artificial Intelligence & Machine Learning (AI/ML)
*   **Python**: Core programming language for logic and data processing.
*   **Streamlit**: Framework for building the interactive data dashboard.
*   **Pandas**: For data manipulation and analysis.
*   **Plotly**: For interactive data visualizations.
*   **Scikit-learn**: For implementing anomaly detection algorithms.

### Blockchain & Smart Contracts
*   **Solidity**: Language for writing smart contracts (`EvidenceRegistry.sol`).
*   **Hardhat**: Ethereum development environment for compiling, deploying, and testing contracts.
*   **Ethers.js**: Library for interacting with the blockchain from the frontend/backend.
*   **Localhost Network**: Runs on a local Hardhat node.

### Backend & Frontend
*   **Node.js & Express.js**: Handles backend API logic and evidence logging.
*   **HTML, CSS, JavaScript**: Provides the user interface for the admin and records pages.

## Project Structure
- `marine-forensics blockchain/`: Contains the Blockchain, Backend, and Frontend web components.
    - `contracts/`: Solidity smart contracts.
    - `backend/`: Node.js server.
    - `frontend/`: HTML/JS user interfaces.
- `ai-detect-anomalies-navigation/`: Contains the Python AI models and Streamlit dashboard.

## Getting Started

### 1. Blockchain Setup
Navigate to the blockchain directory and start the local node:
```bash
cd "marine-forensics blockchain"
npm install
npx hardhat node
```
Open a **new terminal**, deploy the contracts:
```bash
cd "marine-forensics blockchain"
npx hardhat run --network localhost scripts/deploy.js
```

### 2. Backend Server
In the blockchain directory, start the backend:
```bash
node backend/index.js
```

### 3. AI Dashboard
Navigate to the AI directory and run the dashboard:
```bash
cd "ai-detect-anomalies-navigation"
pip install -r requirements.txt
streamlit run maritime_cybersecurity_dashboard_FINAL.py
```
