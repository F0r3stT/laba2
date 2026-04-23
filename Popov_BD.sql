-- 0. Справочники статусов
CREATE TABLE vulnerability_status (
    id_status SERIAL PRIMARY KEY,
    status_name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE incident_status (
    id_status SERIAL PRIMARY KEY,
    status_name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE implementation_status (
    id_status SERIAL PRIMARY KEY,
    status_name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 1. Таблица подразделений
CREATE TABLE department (
    id_department SERIAL PRIMARY KEY,
    dept_name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Таблица уровней критичности
CREATE TABLE criticality_level (
    id_severity SERIAL PRIMARY KEY,
    severity_name VARCHAR(20) NOT NULL UNIQUE,
    cvss_min NUMERIC(3,1) CHECK (cvss_min >= 0 AND cvss_min <= 10),
    cvss_max NUMERIC(3,1) CHECK (cvss_max >= 0 AND cvss_max <= 10),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Таблица источников обнаружения
CREATE TABLE discovery_source (
    id_source SERIAL PRIMARY KEY,
    source_name VARCHAR(100) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Таблица мер устранения
CREATE TABLE remediation_measure (
    id_measure SERIAL PRIMARY KEY,
    measure_name VARCHAR(150) NOT NULL,
    instruction TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 5. Таблица сотрудников (зависит от подразделения)
CREATE TABLE employee (
    id_employee SERIAL PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    position VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    id_department INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_employee_dept FOREIGN KEY (id_department) 
        REFERENCES department(id_department) ON DELETE CASCADE
);

-- 6. Таблица информационных активов (зависит от подразделения)
CREATE TABLE asset (
    id_asset SERIAL PRIMARY KEY,
    asset_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(15) NOT NULL,
    asset_type VARCHAR(50) NOT NULL,
    id_department INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_asset_dept FOREIGN KEY (id_department) 
        REFERENCES department(id_department) ON DELETE CASCADE
);

-- 7. Таблица уязвимостей (зависит от активов, критичности, источников и статуса)
CREATE TABLE vulnerability (
    id_vulnerability SERIAL PRIMARY KEY,
    cve_id VARCHAR(20),
    description TEXT NOT NULL,
    id_status INT NOT NULL,
    id_asset INT NOT NULL,
    id_severity INT NOT NULL,
    id_source INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_vuln_status FOREIGN KEY (id_status) 
        REFERENCES vulnerability_status(id_status) ON DELETE RESTRICT,
    CONSTRAINT fk_vuln_asset FOREIGN KEY (id_asset) 
        REFERENCES asset(id_asset) ON DELETE CASCADE,
    CONSTRAINT fk_vuln_severity FOREIGN KEY (id_severity) 
        REFERENCES criticality_level(id_severity),
    CONSTRAINT fk_vuln_source FOREIGN KEY (id_source) 
        REFERENCES discovery_source(id_source)
);

-- 8. Таблица инцидентов (зависит от уязвимостей, сотрудников и статуса)
CREATE TABLE incident (
    id_incident SERIAL PRIMARY KEY,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL,
    id_status INT NOT NULL,
    id_vulnerability INT NOT NULL,
    id_employee INT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_incident_status FOREIGN KEY (id_status) 
        REFERENCES incident_status(id_status) ON DELETE RESTRICT,
    CONSTRAINT fk_incident_vuln FOREIGN KEY (id_vulnerability) 
        REFERENCES vulnerability(id_vulnerability) ON DELETE CASCADE,
    CONSTRAINT fk_incident_employee FOREIGN KEY (id_employee) 
        REFERENCES employee(id_employee) ON DELETE SET NULL
);

-- 9. Промежуточная таблица: Применение мер 
CREATE TABLE measure_application (
    id_application SERIAL PRIMARY KEY,
    id_vulnerability INT NOT NULL,
    id_measure INT NOT NULL,
    id_status INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_app_status FOREIGN KEY (id_status) 
        REFERENCES implementation_status(id_status) ON DELETE RESTRICT,
    CONSTRAINT fk_app_vuln FOREIGN KEY (id_vulnerability) 
        REFERENCES vulnerability(id_vulnerability) ON DELETE CASCADE,
    CONSTRAINT fk_app_measure FOREIGN KEY (id_measure) 
        REFERENCES remediation_measure(id_measure) ON DELETE CASCADE,
    CONSTRAINT uq_vuln_measure UNIQUE (id_vulnerability, id_measure)
);
