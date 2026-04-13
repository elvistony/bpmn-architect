# Deployment and Getting Started

BPMN Architect is built primarily to be managed via a reverse-proxy (such as IIS), specifically catering to Windows Server environments running Active Directory.

## 1. Local Development Setup

To run the application locally for testing or development:

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-org/bpmn-architect.git
   cd bpmn-architect
   ```

2. **Create the Virtual Environment**
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Review Configuration**
   Open `config.yaml` and set `auth.method` to `"username,password"` so you can test functionality without an IIS domain controller. Configure your mock admin credentials under `auth.credentials`.

5. **Start the Uvicorn Server**
   ```bash
   python -m uvicorn main:app --port 8000 --reload
   ```
   Navigate to `http://127.0.0.1:8000` to view the application.

## 2. Production Deployment (Microsoft IIS)

The primary deployment strategy uses **Uvicorn (ASGI)** running behind **Microsoft IIS**.

### Step 2.1: Server Setup
1. Validate that the Python Virtual Environment runs structurally sound on the server by running Uvicorn manually on `127.0.0.1:8000`.
2. Secure your `config.yaml` parameters (Database URL, admin roles, paths). Set `auth.method` to `"iis-header"`.

### Step 2.2: IIS Reverse Proxy & Security
1. Ensure the **URL Rewrite** module is installed mapping IIS incoming traffic (`Port 80/443`) to `http://127.0.0.1:8000`.
2. Enable **Windows Authentication** in the IIS application bindings.
3. Construct IIS rewriting rules to inject the authenticated AD username (e.g., `DOMAIN\Username`) into an HTTP header explicitly titled `X-Forwarded-User`.

> [!CAUTION]
> The internal Uvicorn Python application **MUST** bind exclusively to `127.0.0.1`. Never expose `0.0.0.0`. Binding to Localhost prevents malicious actors from circumventing IIS and directly spoofing the `X-Forwarded-User` header.

## 3. Storage Dependencies

The system manages files locally in the `diagram_storage/` folder (configured via `storage.diagram_path`). Always ensure that the IIS application pool identity (`IIS_IUSRS`) or the daemon running Uvicorn has **Full Control** (Read/Write) access to this storage directory, as the `.tmp` atomic file write handler requires write-level permissions.
