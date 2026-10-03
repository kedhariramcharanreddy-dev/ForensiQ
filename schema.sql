CREATE DATABASE IF NOT EXISTS forensiq CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE forensiq;

CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(190) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(60) NOT NULL DEFAULT 'Investigator',
  created_at DATETIME NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cases (
  id INT PRIMARY KEY AUTO_INCREMENT,
  case_number VARCHAR(80) NOT NULL UNIQUE,
  title VARCHAR(180) NOT NULL,
  description TEXT,
  status ENUM('Active','Under Review','Closed') NOT NULL DEFAULT 'Active',
  priority ENUM('Low','Medium','High') NOT NULL DEFAULT 'Medium',
  investigator VARCHAR(120),
  created_at DATETIME NOT NULL,
  INDEX idx_cases_status(status),
  INDEX idx_cases_priority(priority)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS evidence (
  id INT PRIMARY KEY AUTO_INCREMENT,
  case_id INT NOT NULL,
  evidence_code VARCHAR(80) NOT NULL UNIQUE,
  name VARCHAR(180) NOT NULL,
  category VARCHAR(80) NOT NULL,
  source VARCHAR(180),
  description TEXT,
  file_name VARCHAR(255),
  storage_name VARCHAR(320),
  file_hash CHAR(64),
  file_size BIGINT DEFAULT 0,
  mime_type VARCHAR(160),
  integrity ENUM('Verified','Mismatch','Missing','Pending') NOT NULL DEFAULT 'Verified',
  ai_risk ENUM('Low','Medium','High','Critical','Pending') NOT NULL DEFAULT 'Pending',
  ai_summary TEXT,
  created_at DATETIME NOT NULL,
  collected_at DATETIME NOT NULL,
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE,
  INDEX idx_evidence_case(case_id),
  INDEX idx_evidence_risk(ai_risk),
  INDEX idx_evidence_hash(file_hash)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS custody (
  id INT PRIMARY KEY AUTO_INCREMENT,
  evidence_id INT NOT NULL,
  action VARCHAR(60) NOT NULL,
  from_person VARCHAR(120),
  to_person VARCHAR(120),
  location VARCHAR(180),
  notes TEXT,
  timestamp DATETIME NOT NULL,
  FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
  INDEX idx_custody_evidence(evidence_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NULL,
  action VARCHAR(80) NOT NULL,
  entity_type VARCHAR(60) NOT NULL,
  entity_id INT NULL,
  details TEXT,
  created_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_audit_created(created_at),
  INDEX idx_audit_entity(entity_type, entity_id)
) ENGINE=InnoDB;
