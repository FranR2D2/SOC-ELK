#!/usr/bin/env python3
# ═══════════════════════════════════════════════
# DLP Agent v1.0 — Data Loss Prevention Monitor
# Integración con SOC-ELK SIEM
# ═══════════════════════════════════════════════

import os
import socket
import json
import time
import datetime
import hashlib
from pathlib import Path

# ── Configuración ──────────────────────────────
LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5514
USUARIO       = os.getenv("USER", "unknown")
HOSTNAME      = socket.gethostname()

# Directorios a monitorizar
DIRS_MONITORIZAR = [
    os.path.expanduser("~/Documentos"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

# Extensiones sensibles
EXTENSIONES_SENSIBLES = [
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".doc", ".xls", ".csv", ".txt",
    ".zip", ".rar", ".7z", ".tar",
    ".key", ".pem", ".p12", ".pfx"
]

# Umbrales de alerta
UMBRAL_ARCHIVOS_MINUTO = 10
UMBRAL_TAMANO_GB       = 2.0  # 2GB umbral real
UMBRAL_SENSIBLES_MIN   = 5    # mínimo 5 archivos sensibles
HORA_INICIO_NOCHE      = 22
HORA_FIN_NOCHE         = 6

# ── Funciones ──────────────────────────────────

def enviar_alerta(evento):
    """Envía evento DLP a Logstash via UDP"""
    try:
        mensaje = json.dumps(evento)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(f"<14>{mensaje}\n".encode(), (LOGSTASH_HOST, LOGSTASH_PORT))
        sock.close()
        print(f"  🚨 ALERTA enviada: {evento['dlp_rule']}")
    except Exception as e:
        print(f"  ❌ Error enviando alerta: {e}")

def crear_evento(regla, severidad, descripcion, detalles={}):
    """Crea un evento DLP estructurado"""
    return {
        "timestamp":    datetime.datetime.now().isoformat(),
        "event_type":   "DLP",
        "dlp_rule":     regla,
        "severity":     severidad,
        "description":  descripcion,
        "user":         USUARIO,
        "hostname":     HOSTNAME,
        "mitre_tactic": "TA0010",
        "mitre_tech":   "T1048",
        **detalles
    }

def escanear_directorio(directorio):
    """Escanea un directorio y retorna info de archivos"""
    archivos = []
    try:
        for root, dirs, files in os.walk(directorio):
            for f in files:
                ruta = os.path.join(root, f)
                try:
                    stat = os.stat(ruta)
                    archivos.append({
                        "ruta":      ruta,
                        "extension": Path(f).suffix.lower(),
                        "tamano":    stat.st_size,
                        "modificado": stat.st_mtime
                    })
                except:
                    pass
    except:
        pass
    return archivos

def detectar_acceso_nocturno():
    """Detecta accesos fuera de horario laboral"""
    hora = datetime.datetime.now().hour
    if hora >= HORA_INICIO_NOCHE or hora < HORA_FIN_NOCHE:
        evento = crear_evento(
            regla="ACCESO_NOCTURNO",
            severidad="MEDIA",
            descripcion=f"Actividad detectada fuera de horario laboral ({hora:02d}:00h)",
            detalles={"hora_acceso": hora}
        )
        enviar_alerta(evento)
        return True
    return False

def detectar_archivos_sensibles(archivos):
    """Detecta copia masiva de archivos sensibles"""
    sensibles = [a for a in archivos if a["extension"] in EXTENSIONES_SENSIBLES]
    
    if len(sensibles) >= UMBRAL_ARCHIVOS_MINUTO:
        tamano_total = sum(a["tamano"] for a in sensibles)
        tamano_gb    = tamano_total / (1024**3)
        
        evento = crear_evento(
            regla="COPIA_MASIVA_ARCHIVOS_SENSIBLES",
            severidad="ALTA",
            descripcion=f"Se detectaron {len(sensibles)} archivos sensibles ({tamano_gb:.2f}GB)",
            detalles={
                "num_archivos":    len(sensibles),
                "tamano_total_gb": round(tamano_gb, 3),
                "extensiones":     list(set(a["extension"] for a in sensibles))
            }
        )
        enviar_alerta(evento)
        return True
    return False

def detectar_transferencia_grande(archivos):
    """Detecta transferencia de grandes volúmenes de datos"""
    tamano_total = sum(a["tamano"] for a in archivos)
    tamano_gb    = tamano_total / (1024**3)
    
    if tamano_gb >= UMBRAL_TAMANO_GB:
        evento = crear_evento(
            regla="TRANSFERENCIA_DATOS_GRANDE",
            severidad="CRITICA",
            descripcion=f"Transferencia de {tamano_gb:.2f}GB detectada",
            detalles={
                "tamano_gb":    round(tamano_gb, 3),
                "num_archivos": len(archivos)
            }
        )
        enviar_alerta(evento)
        return True
    return False

def detectar_usb():
    """Detecta dispositivos USB y archivos copiados"""
    dispositivos = []
    archivos_usb = []

    # Buscar todos los puntos de montaje bajo /media y /mnt
    for base in ["/media", "/mnt"]:
        if not os.path.exists(base):
            continue
        # Comprobar el propio directorio
        if os.path.ismount(base):
            dispositivos.append(base)
            archivos_usb.extend(escanear_directorio(base))
        # Comprobar subdirectorios directos
        for entry in os.listdir(base):
            ruta = os.path.join(base, entry)
            if os.path.ismount(ruta):
                dispositivos.append(ruta)
                archivos_usb.extend(escanear_directorio(ruta))
            elif os.path.isdir(ruta):
                for sub in os.listdir(ruta):
                    sub_ruta = os.path.join(ruta, sub)
                    if os.path.ismount(sub_ruta):
                        dispositivos.append(sub_ruta)
                        archivos_usb.extend(escanear_directorio(sub_ruta))

    if dispositivos:
        tamano_total = sum(a["tamano"] for a in archivos_usb)
        tamano_gb    = tamano_total / (1024**3)
        sensibles    = [a for a in archivos_usb if a["extension"] in EXTENSIONES_SENSIBLES]

        # Alerta base — USB conectado
        evento = crear_evento(
            regla="USB_DETECTADO",
            severidad="MEDIA",
            descripcion=f"USB conectado: {len(archivos_usb)} archivos ({tamano_gb:.2f}GB)",
            detalles={
                "dispositivos_usb":   dispositivos,
                "num_archivos":       len(archivos_usb),
                "tamano_gb":          round(tamano_gb, 3),
                "archivos_sensibles": len(sensibles)
            }
        )
        enviar_alerta(evento)

        # Alerta crítica — volumen grande
        if tamano_gb >= UMBRAL_TAMANO_GB:
            evento2 = crear_evento(
                regla="EXFILTRACION_USB_CONFIRMADA",
                severidad="CRITICA",
                descripcion=f"⚠️ {tamano_gb:.2f}GB copiados al USB — posible exfiltración",
                detalles={
                    "dispositivos_usb":   dispositivos,
                    "tamano_gb":          round(tamano_gb, 3),
                    "num_archivos":       len(archivos_usb),
                    "archivos_sensibles": len(sensibles),
                    "extensiones":        list(set(a["extension"] for a in sensibles))
                }
            )
            enviar_alerta(evento2)

        # Alerta alta — archivos sensibles en USB
        if len(sensibles) > 0:
            evento3 = crear_evento(
                regla="ARCHIVOS_SENSIBLES_EN_USB",
                severidad="ALTA",
                descripcion=f"{len(sensibles)} archivos sensibles detectados en USB",
                detalles={
                    "dispositivos_usb": dispositivos,
                    "num_sensibles":    len(sensibles),
                    "extensiones":      list(set(a["extension"] for a in sensibles)),
                    "tamano_gb":        round(tamano_gb, 3)
                }
            )
            enviar_alerta(evento3)

        return True
    return False

# ── Main ───────────────────────────────────────

def main():
    print("""
╔══════════════════════════════════════════╗
║       DLP Agent v1.0 — SOC-ELK          ║
║   Data Loss Prevention Monitor          ║
╚══════════════════════════════════════════╝
    """)
    print(f"  👤 Usuario:  {USUARIO}")
    print(f"  💻 Hostname: {HOSTNAME}")
    print(f"  📁 Monitorizando: {DIRS_MONITORIZAR}")
    print(f"\n  ⏳ Iniciando monitorización...\n")

    while True:
        print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Escaneando...")

        # Detectar acceso nocturno
        detectar_acceso_nocturno()

        # Detectar USB
        detectar_usb()

        # Escanear directorios
        todos_archivos = []
        for directorio in DIRS_MONITORIZAR:
            if os.path.exists(directorio):
                archivos = escanear_directorio(directorio)
                todos_archivos.extend(archivos)
                print(f"  📂 {directorio}: {len(archivos)} archivos")

        # Detectar archivos sensibles
        detectar_archivos_sensibles(todos_archivos)

        # Detectar transferencia grande
        detectar_transferencia_grande(todos_archivos)

        print(f"  ✅ Escaneo completado. Próximo en 60 segundos...")
        time.sleep(60)

if __name__ == "__main__":
    main()
