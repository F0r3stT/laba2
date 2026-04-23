@startuml
' --- Базовые настройки для компактности и ГОСТ ---
skinparam linetype ortho
skinparam shadowing false
skinparam roundcorner 0
skinparam monochrome true
skinparam nodesep 40  ' Расстояние между узлами по горизонтали
skinparam ranksep 40  ' Расстояние между узлами по вертикали
skinparam defaultFontName "Times New Roman"
skinparam defaultFontSize 12

skinparam rectangle {
    BackgroundColor White
    BorderColor Black
}

' --- 1. БЛОК: ПОДРАЗДЕЛЕНИЕ И СОТРУДНИК (Верхний левый угол) ---
rectangle "Подразделение" as dept
rectangle "Название" as dept_name
rectangle "Описание" as dept_desc
rectangle "Создано" as dept_ca

dept -down-> dept_name
dept -right-> dept_desc
dept -left-> dept_ca

rectangle "Сотрудник" as emp
rectangle "ФИО" as emp_name
rectangle "Должность" as emp_pos
rectangle "Email" as emp_mail
rectangle "Обновлено" as emp_ua

emp -down-> emp_name
emp -right-> emp_pos
emp -left-> emp_mail
emp -up-> emp_ua

dept <-- emp

' --- 2. БЛОК: АКТИВ И УЯЗВИМОСТЬ (Центр схемы) ---
rectangle "Информационный актив" as asset
rectangle "IP-адрес" as asset_ip
rectangle "Тип" as asset_type
rectangle "Название актива" as asset_n

asset -down-> asset_ip
asset -left-> asset_type
asset -right-> asset_n
asset -up-> dept

rectangle "Уязвимость" as vuln
rectangle "CVE ID" as vuln_cve
rectangle "Описание" as vuln_desc
rectangle "Статус" as vuln_stat

vuln -down-> vuln_desc
vuln -left-> vuln_cve
vuln -right-> vuln_stat
vuln -up-> asset

' --- 3. БЛОК: КРИТИЧНОСТЬ И ИНЦИДЕНТ (Правая сторона) ---
rectangle "Уровень критичности" as crit
rectangle "Наименование" as crit_name
rectangle "CVSS Min/Max" as crit_mm

crit -down-> crit_name
crit -right-> crit_mm
vuln -right-> crit

rectangle "Инцидент" as inc
rectangle "Дата фиксации" as inc_date
rectangle "Статус инцидента" as inc_stat

inc -down-> inc_date
inc -right-> inc_stat
inc -left-> vuln
inc -up-> emp

' --- 4. БЛОК: МЕРЫ (Нижняя часть) ---
rectangle "Мера устранения" as measure
rectangle "Инструкция" as meas_inst
rectangle "Название меры" as meas_name

measure -down-> meas_inst
measure -right-> meas_name

rectangle "Применение мер" as app
rectangle "Статус вып." as app_stat
rectangle "Дата изм." as app_ua

app -down-> app_stat
app -right-> app_ua
app -left-> measure
app -up-> vuln

@enduml