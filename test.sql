-- 1. Заполняем справочники статусов
INSERT INTO vulnerability_status (status_name) VALUES ('Обнаружена'), ('В работе'), ('Устранена');
INSERT INTO incident_status (status_name) VALUES ('Новый'), ('В работе'), ('Закрыт'), ('Устранен');
INSERT INTO implementation_status (status_name) VALUES ('Запланировано'), ('Выполняется'), ('Завершено');

-- 2. Заполняем подразделения
INSERT INTO department (dept_name, description) VALUES 
('Отдел ИБ', 'Информационная безопасность'), 
('IT-отдел', 'Системное администрирование'), 
('Разработка', 'Создание софта');

-- 3. Заполняем уровни критичности
INSERT INTO criticality_level (severity_name, cvss_min, cvss_max) VALUES 
('Низкий', 0.1, 3.9), 
('Средний', 4.0, 6.9), 
('Высокий', 7.0, 8.9), 
('Критический', 9.0, 10.0);

-- 4. Заполняем источники обнаружения
INSERT INTO discovery_source (source_name, source_type) VALUES 
('Nessus Scanner', 'Автоматический скан'), 
('MaxPatrol', 'Автоматический скан'), 
('Bug Bounty', 'Ручной поиск');

-- 5. Заполняем сотрудников
INSERT INTO employee (full_name, job_title, email, id_department) VALUES 
('Иванов Иван', 'Специалист ИБ', 'ivanov@it.ru', 1),
('Петров Петр', 'Системный администратор', 'petrov@it.ru', 2),
('Смирнов Алексей', 'Аналитик SOC', 'smirnov@it.ru', 1);

-- 6. Заполняем активы
INSERT INTO asset (asset_name, ip_address, asset_type, id_department) VALUES 
('Главный сервер БД', '192.168.1.10', 'Сервер', 2),
('Почтовый сервер', '192.168.1.20', 'Сервер', 2),
('Рабочая станция CEO', '192.168.2.5', 'ПК', 1);

-- 7. Заполняем уязвимости
INSERT INTO vulnerability (id_cve, description, id_status, id_asset, id_severity, id_source) VALUES 
('CVE-2026-0001', 'SQL-инъекция в панели входа', 1, 1, 4, 3), -- Критическая на БД
('CVE-2026-0002', 'Устаревшая версия Nginx', 2, 2, 2, 1),    -- Средняя на почте
('CVE-2026-0003', 'Слабый пароль RDP', 1, 1, 3, 2),          -- Высокая на БД
('CVE-2026-0004', 'Открытый порт 445', 1, 3, 2, 1);          -- Средняя на ПК

-- 8. Заполняем инциденты (даты ставим апрель 2026 для твоего 28 запроса)
INSERT INTO incident (detected_at, description, id_status, id_vulnerability, id_employee) VALUES 
('2026-04-10 10:00:00', 'Попытка эксплуатации SQLi', 2, 1, 1),
('2026-04-15 12:30:00', 'Сканирование портов', 3, 3, 1),
('2026-04-20 15:00:00', 'Брутфорс пароля RDP', 1, 3, 3),
('2026-04-25 09:00:00', 'Обнаружена старая версия ПО', 1, 2, 2);