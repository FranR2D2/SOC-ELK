#!/usr/bin/env python3
# ═══════════════════════════════════════════════
# DLP Test — Simulador de eventos DLP
# ═══════════════════════════════════════════════

import socket
import json
import time
import datetime

LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5514

def enviar_evento(evento):
    mensaje = json.dumps(evento)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(f"<14>{mensaje}\n".encode(), (LOGSTASH_HOST, LOGSTASH_PORT))
    sock.close()
    print(f"  ► {evento['dlp_rule']} enviado")

def simular_copia_masiva():
    print("\n📁 Simulando copia masiva de archivos sensibles...")
    evento = {
        "timestamp":    datetime.datetime.now().isoformat(),
        "event_type":   "DLP",
        "dlp_rule":     "COPIA_MASIVA_ARCHIVOS_SENSIBLES",
        "severity":     "ALTA",
        "description":  "Se detectaron 45 archivos sensibles (2.3GB)",
        "user":         "jgonzalez",
        "hostname":     "PC-JURIDICO-05",
        "mitre_tactic": "TA0010",
        "mitre_tech":   "T1048",
        "num_archivos":  45,
        "tamano_gb":     2.3,
        "extensiones":  [".pdf", ".docx", ".xlsx"]
    }
    enviar_evento(evento)

def simular_acceso_nocturno():
    print("\n🌙 Simulando acceso fuera de horario...")
    evento = {
        "timestamp":    datetime.datetime.now().isoformat(),
        "event_type":   "DLP",
        "dlp_rule":     "ACCESO_NOCTURNO",
        "severity":     "MEDIA",
        "description":  "Actividad detectada fuera de horario laboral (02:34h)",
        "user":         "jgonzalez",
        "hostname":     "PC-JURIDICO-05",
        "mitre_tactic": "TA0010",
        "mitre_tech":   "T1078",
        "hora_acceso":  2
    }
    enviar_evento(evento)

def simular_usb():
    print("\n🔌 Simulando conexión de USB...")
    evento = {
        "timestamp":    datetime.datetime.now().isoformat(),
        "event_type":   "DLP",
        "dlp_rule":     "USB_DETECTADO",
        "severity":     "ALTA",
        "description":  "Dispositivo USB montado en /media/usb0",
        "user":         "jgonzalez",
        "hostname":     "PC-JURIDICO-05",
        "mitre_tactic": "TA0010",
        "mitre_tech":   "T1052",
        "dispositivo":  "/media/usb0"
    }
    enviar_evento(evento)

def simular_transferencia_grande():
    print("\n📤 Simulando transferencia de datos grande...")
    evento = {
        "timestamp":    datetime.datetime.now().isoformat(),
        "event_type":   "DLP",
        "dlp_rule":     "TRANSFERENCIA_DATOS_GRANDE",
        "severity":     "CRITICA",
        "description":  "Transferencia de 15.7GB detectada",
        "user":         "jgonzalez",
        "hostname":     "PC-JURIDICO-05",
        "mitre_tactic": "TA0010",
        "mitre_tech":   "T1048",
        "tamano_gb":    15.7,
        "num_archivos": 234
    }
    enviar_evento(evento)

print("""
╔══════════════════════════════════════════╗
║      DLP Test Simulator v1.0            ║
║   Simulador de eventos de exfiltración  ║
╚══════════════════════════════════════════╝
""")

print("Selecciona el escenario:")
print("  1 - Copia masiva de archivos sensibles")
print("  2 - Acceso fuera de horario")
print("  3 - USB conectado")
print("  4 - Transferencia de datos grande")
print("  5 - Todos (simular insider threat completo)")

opcion = input("\nOpción: ")

if opcion == "1":
    simular_copia_masiva()
elif opcion == "2":
    simular_acceso_nocturno()
elif opcion == "3":
    simular_usb()
elif opcion == "4":
    simular_transferencia_grande()
elif opcion == "5":
    print("\n🎭 Simulando insider threat completo...")
    print("   (empleado jgonzalez filtrando información)")
    simular_acceso_nocturno()
    time.sleep(1)
    simular_copia_masiva()
    time.sleep(1)
    simular_usb()
    time.sleep(1)
    simular_transferencia_grande()
else:
    print("Opción no válida")

print("\n✅ Revisa Kibana en http://localhost:5601")
