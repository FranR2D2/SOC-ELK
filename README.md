# 🛡️ SOC-ELK — Security Operations Center

> Laboratorio SIEM completo basado en ELK Stack con módulo DLP
> para práctica de ciberseguridad defensiva.

## 🏗️ Stack Tecnológico
- **Elasticsearch** — Almacenamiento de logs
- **Logstash** — Procesamiento y enriquecimiento
- **Kibana** — Dashboards y visualización
- **Elastalert2** — Detección automática de amenazas
- **Docker** — Despliegue containerizado

---

## 🎯 Módulo 1 — SIEM & Detección de Amenazas

| Ataque | MITRE | Severidad |
|--------|-------|-----------|
| Brute Force SSH | T1110 | 🔴 ALTA |
| Port Scan | T1046 | 🟡 MEDIA |
| SQL Injection | T1190 | 🔴 ALTA |

---

## 🔒 Módulo 2 — DLP (Data Loss Prevention)

Sistema de detección de exfiltración de datos con prueba
real documentada — detección de 1.95GB de archivos
sensibles copiados a dispositivo USB.

| Regla | MITRE | Severidad |
|-------|-------|-----------|
| Copia masiva archivos sensibles | T1048 | 🔴 ALTA |
| Acceso fuera de horario | T1078 | 🟡 MEDIA |
| USB conectado | T1052 | 🔴 ALTA |
| Exfiltración USB confirmada (+2GB) | T1052 | 🔴 CRÍTICA |

### Caso de uso real
Detección de insider threat — empleado que copia
documentación confidencial (.pdf, .docx, .xlsx)
a dispositivo USB fuera del horario laboral.

---

## 🚀 Instalación Rápida

```bash
git clone https://github.com/FranR2D2/SOC-ELK.git
cd SOC-ELK
cp .env.example .env
# Editar .env con tus contraseñas
docker compose up -d
```

## 🗺️ MITRE ATT&CK Coverage

### Detección de Amenazas
- T1046 — Network Service Discovery
- T1110 — Brute Force
- T1190 — Exploit Public-Facing Application

### Data Loss Prevention
- T1048 — Exfiltration Over Alternative Protocol
- T1052 — Exfiltration over Physical Medium
- T1078 — Valid Accounts

## 📁 Estructura del Proyecto
SOC-ELK/
├── docker-compose.yml
├── logstash/pipeline/soc.conf
├── scripts/generate-test-logs.py
├── elastalert/
│   ├── config.yml
│   ├── start-elastalert.sh
│   └── rules/
│       ├── brute-force-ssh.yml
│       ├── port-scan.yml
│       ├── sql-injection.yml
│       ├── dlp-mass-copy.yml
│       ├── dlp-after-hours.yml
│       ├── dlp-usb.yml
│       └── dlp-usb-exfil.yml
└── dlp/
└── agent/
├── dlp-agent.py
└── dlp-test.py

## 👨‍💻 Autor
**FranR2D2** — SOC Analyst Jr.
