-- ЗАПРОСЫ (21–30)

-- 21. Уязвимости выше среднего уровня критичности
SELECT * FROM vulnerability 
WHERE id_severity IN (
    SELECT id_severity FROM criticality_level 
    WHERE (cvss_min + cvss_max)/2 > (SELECT AVG((cvss_min + cvss_max)/2) FROM criticality_level)
);

-- 22. Сотрудники, у которых инцидентов больше среднего
SELECT e.full_name, COUNT(i.id_incident) as total_incidents
FROM employee e
JOIN incident i ON e.id_employee = i.id_employee
GROUP BY e.id_employee
HAVING COUNT(i.id_incident) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM incident GROUP BY id_employee) sub);

-- 23. Актив с максимальным количеством инцидентов
SELECT a.asset_name, COUNT(i.id_incident) as inc_count
FROM asset a
JOIN vulnerability v ON a.id_asset = v.id_asset
JOIN incident i ON v.id_vulnerability = i.id_vulnerability
GROUP BY a.id_asset
ORDER BY inc_count DESC LIMIT 1;

-- 24. Типы источников угроз, которые встречаются чаще среднего
SELECT ds.source_name, COUNT(v.id_vulnerability) as usage_count
FROM discovery_source ds
JOIN vulnerability v ON ds.id_source = v.id_source
GROUP BY ds.id_source
HAVING COUNT(v.id_vulnerability) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM vulnerability GROUP BY id_source) sub);

-- 25. Инциденты с максимальной критичностью уязвимости
SELECT * FROM incident 
WHERE id_vulnerability IN (
    SELECT id_vulnerability FROM vulnerability 
    WHERE id_severity = (SELECT id_severity FROM criticality_level ORDER BY cvss_max DESC LIMIT 1)
);

-- 26. Сотрудники с назначениями выше среднего по системе
SELECT e.full_name, COUNT(i.id_incident) as assignments
FROM employee e
JOIN incident i ON e.id_employee = i.id_employee
GROUP BY e.id_employee
HAVING COUNT(i.id_incident) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM incident GROUP BY id_employee) sub);

-- 27. Активы с количеством уязвимостей выше среднего
SELECT a.asset_name, COUNT(v.id_vulnerability) as vulns
FROM asset a
JOIN vulnerability v ON a.id_asset = v.id_asset
GROUP BY a.id_asset
HAVING COUNT(v.id_vulnerability) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM vulnerability GROUP BY id_asset) sub);

-- 28. Угрозы по инцидентам позже средней даты
SELECT DISTINCT v.id_vulnerability, v.id_cve
FROM vulnerability v
JOIN incident i ON v.id_vulnerability = i.id_vulnerability
WHERE i.detected_at > (
    SELECT TO_TIMESTAMP(AVG(EXTRACT(EPOCH FROM detected_at))) FROM incident
);

-- 29. Сотрудники, работавшие с самыми частыми уязвимостями
SELECT DISTINCT e.full_name
FROM employee e
JOIN incident i ON e.id_employee = i.id_employee
WHERE i.id_vulnerability IN (
    SELECT id_vulnerability FROM incident GROUP BY id_vulnerability ORDER BY COUNT(*) DESC LIMIT 3
);

-- 30. Инциденты на активах, где и уязвимостей, и угроз выше среднего
SELECT i.* FROM incident i
JOIN vulnerability v ON i.id_vulnerability = v.id_vulnerability
WHERE v.id_asset IN (
    SELECT id_asset FROM vulnerability GROUP BY id_asset 
    HAVING COUNT(*) > (SELECT AVG(c) FROM (SELECT COUNT(*) as c FROM vulnerability GROUP BY id_asset) s)
);

-- ФУНКЦИИ (8–10)

-- 8. Количество открытых инцидентов на текущую дату
CREATE OR REPLACE FUNCTION get_open_incidents_count() 
RETURNS INTEGER AS $$
BEGIN
    RETURN (SELECT COUNT(*) FROM incident i 
            JOIN incident_status s ON i.id_status = s.id_status 
            WHERE s.status_name NOT IN ('Устранен', 'Закрыт'));
END;
$$ LANGUAGE plpgsql;

-- 9. Среднее количество уязвимостей на один актив
CREATE OR REPLACE FUNCTION get_avg_vulns_per_asset() 
RETURNS NUMERIC AS $$
BEGIN
    RETURN (SELECT CAST(COUNT(*) AS NUMERIC) / NULLIF(COUNT(DISTINCT id_asset), 0) FROM vulnerability);
END;
$$ LANGUAGE plpgsql;

-- 10. Сотрудники для инцидентов с высоким уровнем критичности
CREATE OR REPLACE FUNCTION get_high_crit_employees() 
RETURNS TABLE(emp_name VARCHAR) AS $$
BEGIN
    RETURN QUERY 
    SELECT DISTINCT CAST(e.full_name AS VARCHAR) FROM employee e
    JOIN incident i ON e.id_employee = i.id_employee
    JOIN vulnerability v ON i.id_vulnerability = v.id_vulnerability
    JOIN criticality_level cl ON v.id_severity = cl.id_severity
    WHERE cl.severity_name IN ('Высокий', 'Критический');
END;
$$ LANGUAGE plpgsql;

-- ТРИГГЕРЫ (8–10)

-- 8. Авто-обновление счетчика инцидентов у актива
CREATE OR REPLACE FUNCTION update_asset_stats() RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        UPDATE asset SET incident_count = incident_count + 1 
        WHERE id_asset = (SELECT id_asset FROM vulnerability WHERE id_vulnerability = NEW.id_vulnerability);
    ELSIF (TG_OP = 'DELETE') THEN
        UPDATE asset SET incident_count = incident_count - 1 
        WHERE id_asset = (SELECT id_asset FROM vulnerability WHERE id_vulnerability = OLD.id_vulnerability);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_asset_incident_count ON incident;
CREATE TRIGGER trg_update_asset_incident_count
AFTER INSERT OR DELETE ON incident
FOR EACH ROW EXECUTE FUNCTION update_asset_stats();

-- 9. Проверка сотрудника перед переводом в «в работе»
CREATE OR REPLACE FUNCTION check_assignee_exists() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id_status = (SELECT id_status FROM incident_status WHERE status_name = 'В работе') 
       AND NEW.id_employee IS NULL THEN
        RAISE EXCEPTION 'Нельзя перевести в работу без ответственного сотрудника!';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_check_before_work ON incident;
CREATE TRIGGER trg_check_before_work
BEFORE UPDATE ON incident
FOR EACH ROW EXECUTE FUNCTION check_assignee_exists();

-- 10. Запись даты завершения при закрытии
CREATE OR REPLACE FUNCTION set_close_date() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id_status = (SELECT id_status FROM incident_status WHERE status_name = 'Закрыт') THEN
        NEW.updated_at = CURRENT_TIMESTAMP;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_incident_close_date ON incident;
CREATE TRIGGER trg_incident_close_date
BEFORE UPDATE ON incident
FOR EACH ROW EXECUTE FUNCTION set_close_date();