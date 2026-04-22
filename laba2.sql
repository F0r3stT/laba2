{\rtf1\ansi\ansicpg1251\cocoartf2868
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\froman\fcharset0 Times-Roman;\f1\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;}
{\*\expandedcolortbl;;\cssrgb\c0\c0\c0;}
\paperw11900\paperh16840\margl1440\margr1440\vieww29200\viewh15460\viewkind0
\deftab720
\pard\pardeftab720\partightenfactor0

\f0\fs24 \cf0 \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 -- \uc0\u1047 \u1040 \u1055 \u1056 \u1054 \u1057 \u1067  (21\'9630)
\f1 \kerning1\expnd0\expndtw0 \outl0\strokewidth0 \
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0 -- 21. \uc0\u1059 \u1103 \u1079 \u1074 \u1080 \u1084 \u1086 \u1089 \u1090 \u1080  \u1074 \u1099 \u1096 \u1077  \u1089 \u1088 \u1077 \u1076 \u1085 \u1077 \u1075 \u1086  \u1091 \u1088 \u1086 \u1074 \u1085 \u1103  \u1082 \u1088 \u1080 \u1090 \u1080 \u1095 \u1085 \u1086 \u1089 \u1090 \u1080 \
SELECT * FROM vulnerability \
WHERE id_severity IN (\
    SELECT id_severity FROM criticality_level \
    WHERE (cvss_min + cvss_max)/2 > (SELECT AVG((cvss_min + cvss_max)/2) FROM criticality_level)\
);\
\
-- 22. \uc0\u1057 \u1086 \u1090 \u1088 \u1091 \u1076 \u1085 \u1080 \u1082 \u1080 , \u1091  \u1082 \u1086 \u1090 \u1086 \u1088 \u1099 \u1093  \u1080 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1086 \u1074  \u1073 \u1086 \u1083 \u1100 \u1096 \u1077  \u1089 \u1088 \u1077 \u1076 \u1085 \u1077 \u1075 \u1086 \
SELECT e.full_name, COUNT(i.id_incident) as total_incidents\
FROM employee e\
JOIN incident i ON e.id_employee = i.id_employee\
GROUP BY e.id_employee\
HAVING COUNT(i.id_incident) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM incident GROUP BY id_employee) sub);\
\
-- 23. \uc0\u1040 \u1082 \u1090 \u1080 \u1074  \u1089  \u1084 \u1072 \u1082 \u1089 \u1080 \u1084 \u1072 \u1083 \u1100 \u1085 \u1099 \u1084  \u1082 \u1086 \u1083 \u1080 \u1095 \u1077 \u1089 \u1090 \u1074 \u1086 \u1084  \u1080 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1086 \u1074 \
SELECT a.asset_name, COUNT(i.id_incident) as inc_count\
FROM asset a\
JOIN vulnerability v ON a.id_asset = v.id_asset\
JOIN incident i ON v.id_vulnerability = i.id_vulnerability\
GROUP BY a.id_asset\
ORDER BY inc_count DESC LIMIT 1;\
\
-- 24. \uc0\u1058 \u1080 \u1087 \u1099  \u1080 \u1089 \u1090 \u1086 \u1095 \u1085 \u1080 \u1082 \u1086 \u1074  \u1091 \u1075 \u1088 \u1086 \u1079 , \u1082 \u1086 \u1090 \u1086 \u1088 \u1099 \u1077  \u1074 \u1089 \u1090 \u1088 \u1077 \u1095 \u1072 \u1102 \u1090 \u1089 \u1103  \u1095 \u1072 \u1097 \u1077  \u1089 \u1088 \u1077 \u1076 \u1085 \u1077 \u1075 \u1086 \
SELECT ds.source_name, COUNT(v.id_vulnerability) as usage_count\
FROM discovery_source ds\
JOIN vulnerability v ON ds.id_source = v.id_source\
GROUP BY ds.id_source\
HAVING COUNT(v.id_vulnerability) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM vulnerability GROUP BY id_source) sub);\
\
-- 25. \uc0\u1048 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1099  \u1089  \u1084 \u1072 \u1082 \u1089 \u1080 \u1084 \u1072 \u1083 \u1100 \u1085 \u1086 \u1081  \u1082 \u1088 \u1080 \u1090 \u1080 \u1095 \u1085 \u1086 \u1089 \u1090 \u1100 \u1102  \u1091 \u1103 \u1079 \u1074 \u1080 \u1084 \u1086 \u1089 \u1090 \u1080 \
SELECT * FROM incident \
WHERE id_vulnerability IN (\
    SELECT id_vulnerability FROM vulnerability \
    WHERE id_severity = (SELECT id_severity FROM criticality_level ORDER BY cvss_max DESC LIMIT 1)\
);\
\
-- 26. \uc0\u1057 \u1086 \u1090 \u1088 \u1091 \u1076 \u1085 \u1080 \u1082 \u1080  \u1089  \u1085 \u1072 \u1079 \u1085 \u1072 \u1095 \u1077 \u1085 \u1080 \u1103 \u1084 \u1080  \u1074 \u1099 \u1096 \u1077  \u1089 \u1088 \u1077 \u1076 \u1085 \u1077 \u1075 \u1086  \u1087 \u1086  \u1089 \u1080 \u1089 \u1090 \u1077 \u1084 \u1077 \
SELECT e.full_name, COUNT(i.id_incident) as assignments\
FROM employee e\
JOIN incident i ON e.id_employee = i.id_employee\
GROUP BY e.id_employee\
HAVING COUNT(i.id_incident) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM incident GROUP BY id_employee) sub);\
\
-- 27. \uc0\u1040 \u1082 \u1090 \u1080 \u1074 \u1099  \u1089  \u1082 \u1086 \u1083 \u1080 \u1095 \u1077 \u1089 \u1090 \u1074 \u1086 \u1084  \u1091 \u1103 \u1079 \u1074 \u1080 \u1084 \u1086 \u1089 \u1090 \u1077 \u1081  \u1074 \u1099 \u1096 \u1077  \u1089 \u1088 \u1077 \u1076 \u1085 \u1077 \u1075 \u1086 \
SELECT a.asset_name, COUNT(v.id_vulnerability) as vulns\
FROM asset a\
JOIN vulnerability v ON a.id_asset = v.id_asset\
GROUP BY a.id_asset\
HAVING COUNT(v.id_vulnerability) > (SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM vulnerability GROUP BY id_asset) sub);\
\
-- 28. \uc0\u1059 \u1075 \u1088 \u1086 \u1079 \u1099  \u1087 \u1086  \u1080 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1072 \u1084  \u1087 \u1086 \u1079 \u1078 \u1077  \u1089 \u1088 \u1077 \u1076 \u1085 \u1077 \u1081  \u1076 \u1072 \u1090 \u1099 \
SELECT DISTINCT v.id_vulnerability, v.id_cve\
FROM vulnerability v\
JOIN incident i ON v.id_vulnerability = i.id_vulnerability\
WHERE i.detected_at > (\
    SELECT TO_TIMESTAMP(AVG(EXTRACT(EPOCH FROM detected_at))) FROM incident\
);\
\
-- 29. \uc0\u1057 \u1086 \u1090 \u1088 \u1091 \u1076 \u1085 \u1080 \u1082 \u1080 , \u1088 \u1072 \u1073 \u1086 \u1090 \u1072 \u1074 \u1096 \u1080 \u1077  \u1089  \u1089 \u1072 \u1084 \u1099 \u1084 \u1080  \u1095 \u1072 \u1089 \u1090 \u1099 \u1084 \u1080  \u1091 \u1103 \u1079 \u1074 \u1080 \u1084 \u1086 \u1089 \u1090 \u1103 \u1084 \u1080 \
SELECT DISTINCT e.full_name\
FROM employee e\
JOIN incident i ON e.id_employee = i.id_employee\
WHERE i.id_vulnerability IN (\
    SELECT id_vulnerability FROM incident GROUP BY id_vulnerability ORDER BY COUNT(*) DESC LIMIT 3\
);\
\
-- 30. \uc0\u1048 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1099  \u1085 \u1072  \u1072 \u1082 \u1090 \u1080 \u1074 \u1072 \u1093 , \u1075 \u1076 \u1077  \u1080  \u1091 \u1103 \u1079 \u1074 \u1080 \u1084 \u1086 \u1089 \u1090 \u1077 \u1081 , \u1080  \u1091 \u1075 \u1088 \u1086 \u1079  \u1074 \u1099 \u1096 \u1077  \u1089 \u1088 \u1077 \u1076 \u1085 \u1077 \u1075 \u1086 \
SELECT i.* FROM incident i\
JOIN vulnerability v ON i.id_vulnerability = v.id_vulnerability\
WHERE v.id_asset IN (\
    SELECT id_asset FROM vulnerability GROUP BY id_asset \
    HAVING COUNT(*) > (SELECT AVG(c) FROM (SELECT COUNT(*) as c FROM vulnerability GROUP BY id_asset) s)\
);\
\
-- ==========================================\
-- \uc0\u1060 \u1059 \u1053 \u1050 \u1062 \u1048 \u1048  (8\'9610)\
\
-- 8. \uc0\u1050 \u1086 \u1083 \u1080 \u1095 \u1077 \u1089 \u1090 \u1074 \u1086  \u1086 \u1090 \u1082 \u1088 \u1099 \u1090 \u1099 \u1093  \u1080 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1086 \u1074  \u1085 \u1072  \u1090 \u1077 \u1082 \u1091 \u1097 \u1091 \u1102  \u1076 \u1072 \u1090 \u1091 \
CREATE OR REPLACE FUNCTION get_open_incidents_count() \
RETURNS INTEGER AS $$\
BEGIN\
    RETURN (SELECT COUNT(*) FROM incident i \
            JOIN incident_status s ON i.id_status = s.id_status \
            WHERE s.status_name NOT IN ('\uc0\u1059 \u1089 \u1090 \u1088 \u1072 \u1085 \u1077 \u1085 ', '\u1047 \u1072 \u1082 \u1088 \u1099 \u1090 '));\
END;\
$$ LANGUAGE plpgsql;\
\
-- 9. \uc0\u1057 \u1088 \u1077 \u1076 \u1085 \u1077 \u1077  \u1082 \u1086 \u1083 \u1080 \u1095 \u1077 \u1089 \u1090 \u1074 \u1086  \u1091 \u1103 \u1079 \u1074 \u1080 \u1084 \u1086 \u1089 \u1090 \u1077 \u1081  \u1085 \u1072  \u1086 \u1076 \u1080 \u1085  \u1072 \u1082 \u1090 \u1080 \u1074 \
CREATE OR REPLACE FUNCTION get_avg_vulns_per_asset() \
RETURNS NUMERIC AS $$\
BEGIN\
    RETURN (SELECT CAST(COUNT(*) AS NUMERIC) / NULLIF(COUNT(DISTINCT id_asset), 0) FROM vulnerability);\
END;\
$$ LANGUAGE plpgsql;\
\
-- 10. \uc0\u1057 \u1086 \u1090 \u1088 \u1091 \u1076 \u1085 \u1080 \u1082 \u1080  \u1076 \u1083 \u1103  \u1080 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1086 \u1074  \u1089  \u1074 \u1099 \u1089 \u1086 \u1082 \u1080 \u1084  \u1091 \u1088 \u1086 \u1074 \u1085 \u1077 \u1084  \u1082 \u1088 \u1080 \u1090 \u1080 \u1095 \u1085 \u1086 \u1089 \u1090 \u1080 \
CREATE OR REPLACE FUNCTION get_high_crit_employees() \
RETURNS TABLE(emp_name VARCHAR) AS $$\
BEGIN\
    RETURN QUERY \
    SELECT DISTINCT CAST(e.full_name AS VARCHAR) FROM employee e\
    JOIN incident i ON e.id_employee = i.id_employee\
    JOIN vulnerability v ON i.id_vulnerability = v.id_vulnerability\
    JOIN criticality_level cl ON v.id_severity = cl.id_severity\
    WHERE cl.severity_name IN ('\uc0\u1042 \u1099 \u1089 \u1086 \u1082 \u1080 \u1081 ', '\u1050 \u1088 \u1080 \u1090 \u1080 \u1095 \u1077 \u1089 \u1082 \u1080 \u1081 ');\
END;\
$$ LANGUAGE plpgsql;\
\
-- ==========================================\
-- \uc0\u1058 \u1056 \u1048 \u1043 \u1043 \u1045 \u1056 \u1067  (8\'9610)\
\
-- 8. \uc0\u1040 \u1074 \u1090 \u1086 -\u1086 \u1073 \u1085 \u1086 \u1074 \u1083 \u1077 \u1085 \u1080 \u1077  \u1089 \u1095 \u1077 \u1090 \u1095 \u1080 \u1082 \u1072  \u1080 \u1085 \u1094 \u1080 \u1076 \u1077 \u1085 \u1090 \u1086 \u1074  \u1091  \u1072 \u1082 \u1090 \u1080 \u1074 \u1072 \
CREATE OR REPLACE FUNCTION update_asset_stats() RETURNS TRIGGER AS $$\
BEGIN\
    IF (TG_OP = 'INSERT') THEN\
        UPDATE asset SET incident_count = incident_count + 1 \
        WHERE id_asset = (SELECT id_asset FROM vulnerability WHERE id_vulnerability = NEW.id_vulnerability);\
    ELSIF (TG_OP = 'DELETE') THEN\
        UPDATE asset SET incident_count = incident_count - 1 \
        WHERE id_asset = (SELECT id_asset FROM vulnerability WHERE id_vulnerability = OLD.id_vulnerability);\
    END IF;\
    RETURN NULL;\
END;\
$$ LANGUAGE plpgsql;\
\
DROP TRIGGER IF EXISTS trg_update_asset_incident_count ON incident;\
CREATE TRIGGER trg_update_asset_incident_count\
AFTER INSERT OR DELETE ON incident\
FOR EACH ROW EXECUTE FUNCTION update_asset_stats();\
\
-- 9. \uc0\u1055 \u1088 \u1086 \u1074 \u1077 \u1088 \u1082 \u1072  \u1089 \u1086 \u1090 \u1088 \u1091 \u1076 \u1085 \u1080 \u1082 \u1072  \u1087 \u1077 \u1088 \u1077 \u1076  \u1087 \u1077 \u1088 \u1077 \u1074 \u1086 \u1076 \u1086 \u1084  \u1074  \'ab\u1074  \u1088 \u1072 \u1073 \u1086 \u1090 \u1077 \'bb\
CREATE OR REPLACE FUNCTION check_assignee_exists() RETURNS TRIGGER AS $$\
BEGIN\
    IF NEW.id_status = (SELECT id_status FROM incident_status WHERE status_name = '\uc0\u1042  \u1088 \u1072 \u1073 \u1086 \u1090 \u1077 ') \
       AND NEW.id_employee IS NULL THEN\
        RAISE EXCEPTION '\uc0\u1053 \u1077 \u1083 \u1100 \u1079 \u1103  \u1087 \u1077 \u1088 \u1077 \u1074 \u1077 \u1089 \u1090 \u1080  \u1074  \u1088 \u1072 \u1073 \u1086 \u1090 \u1091  \u1073 \u1077 \u1079  \u1086 \u1090 \u1074 \u1077 \u1090 \u1089 \u1090 \u1074 \u1077 \u1085 \u1085 \u1086 \u1075 \u1086  \u1089 \u1086 \u1090 \u1088 \u1091 \u1076 \u1085 \u1080 \u1082 \u1072 !';\
    END IF;\
    RETURN NEW;\
END;\
$$ LANGUAGE plpgsql;\
\
DROP TRIGGER IF EXISTS trg_check_before_work ON incident;\
CREATE TRIGGER trg_check_before_work\
BEFORE UPDATE ON incident\
FOR EACH ROW EXECUTE FUNCTION check_assignee_exists();\
\
-- 10. \uc0\u1047 \u1072 \u1087 \u1080 \u1089 \u1100  \u1076 \u1072 \u1090 \u1099  \u1079 \u1072 \u1074 \u1077 \u1088 \u1096 \u1077 \u1085 \u1080 \u1103  \u1087 \u1088 \u1080  \u1079 \u1072 \u1082 \u1088 \u1099 \u1090 \u1080 \u1080 \
CREATE OR REPLACE FUNCTION set_close_date() RETURNS TRIGGER AS $$\
BEGIN\
    IF NEW.id_status = (SELECT id_status FROM incident_status WHERE status_name = '\uc0\u1047 \u1072 \u1082 \u1088 \u1099 \u1090 ') THEN\
        NEW.updated_at = CURRENT_TIMESTAMP;\
    END IF;\
    RETURN NEW;\
END;\
$$ LANGUAGE plpgsql;\
\
DROP TRIGGER IF EXISTS trg_incident_close_date ON incident;\
CREATE TRIGGER trg_incident_close_date\
BEFORE UPDATE ON incident\
FOR EACH ROW EXECUTE FUNCTION set_close_date();}