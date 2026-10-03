# ForensiQ — AI-Assisted Smart Digital Forensics Evidence Management System

A college-project-ready Flask + MySQL application for managing digital-forensics cases, evidence, integrity fingerprints, AI-assisted triage, chain of custody, audit logs and evidence reports.

## Stack
- Python / Flask
- MySQL 8+
- Jinja2 HTML templates
- CSS + vanilla JavaScript
- SHA-256 integrity hashing
- Rule-based AI-assisted triage (transparent demo component)

## Demo account
- Email: `admin@forensiq.local`
- Password: `admin123`

## Local setup

### 1. Create the MySQL database
Open MySQL and run:

```sql
SOURCE /absolute/path/to/forensiq_mysql/schema.sql;
```

Or paste the contents of `schema.sql` into MySQL Workbench.

### 2. Configure environment
Copy `.env.example` to `.env` and set your MySQL password.

```bash
cp .env.example .env
```

### 3. Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 4. Start

```bash
python3 app.py
```

Open `http://127.0.0.1:5000`.

## Main capabilities
- Secure login with hashed passwords
- Case management
- Evidence registration and actual file upload
- SHA-256 evidence fingerprinting
- Integrity verification against the stored file
- AI-assisted risk triage with explainable indicators
- Chain-of-custody timeline
- Audit log of major actions
- Search and risk filtering
- CSV evidence report export
- 50 MB upload limit

## Important project note
The AI module is intentionally described as **AI-assisted triage**. It provides transparent indicator-based prioritization and should not be presented as autonomous forensic proof or a replacement for expert examination.

## Deployment
For production/public deployment, use a hosted MySQL-compatible database and set the environment variables in the hosting platform. Do not commit `.env`, passwords, uploaded evidence or the `uploads/` directory to Git.
