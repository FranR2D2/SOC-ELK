# 🛡️ SOC-ELK — Security Operations Center

> Laboratorio SIEM completo basado en ELK Stack 
> para práctica de ciberseguridad defensiva.

## 🏗️ Stack Tecnológico
- **Elasticsearch** — Almacenamiento de logs
- **Logstash** — Procesamiento y enriquecimiento
- **Kibana** — Dashboards y visualización
- **Elastalert2** — Detección automática de amenazas
- **Docker** — Despliegue containerizado

## 🎯 Capacidades de Detección
| Ataque | MITRE | Severidad |
|--------|-------|-----------|
| Brute Force SSH | T1110 | 🔴 ALTA |
| Port Scan | T1046 | 🟡 MEDIA |
| SQL Injection | T1190 | 🔴 ALTA |

## 🚀 Instalación Rápida
```bash
git clone https://github.com/FranR2D2/SOC-ELK.git
cd SOC-ELK
docker compose up -d
```

## 📊 Arquitectura
```
Logs → Logstash → Elasticsearch → Kibana
                      ↓
                 Elastalert2 → Alertas
```

## 🗺️ MITRE ATT&CK Coverage
- T1046 — Network Service Discovery
- T1110 — Brute Force
- T1190 — Exploit Public-Facing Application

## 👨‍💻 Autor
**FranR2D2** — SOC Analyst Jr. en formación
