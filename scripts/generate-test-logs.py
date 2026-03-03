import socket, time, datetime, random

LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5514

ips_atacante = ["192.168.1.105", "185.220.101.47", "45.33.32.156"]
hostnames = ["web-srv01", "win-dc02", "fileserver", "db-server"]
usuarios = ["root", "admin", "administrator", "ubuntu", "pi"]

def enviar_log(mensaje):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(f"<14>{mensaje}\n".encode(), (LOGSTASH_HOST, LOGSTASH_PORT))
        sock.close()
        print(f"  ► {mensaje[:80]}")
    except:
        print(f"  ► {mensaje[:80]}")

def brute_force(cantidad=30):
    print("\n🔐 Simulando ataque Brute Force SSH...")
    ip = random.choice(ips_atacante)
    host = random.choice(hostnames)
    for i in range(cantidad):
        user = random.choice(usuarios)
        ts = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        log = f"{ts} {host} sshd[1234]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
        enviar_log(log)
        time.sleep(0.2)
    print(f"\n  ✅ {cantidad} intentos fallidos enviados")

def port_scan(cantidad=50):
    print("\n🔍 Simulando Port Scan...")
    ip = random.choice(ips_atacante)
    puertos = [21,22,23,25,80,443,445,3306,3389,8080]
    for i in range(cantidad):
        dst = f"10.0.0.{random.randint(1,254)}"
        puerto = random.choice(puertos)
        ts = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        log = f"{ts} firewall kernel: DROP IN=eth0 SRC={ip} DST={dst} PROTO=TCP DPT={puerto} SYN"
        enviar_log(log)
        time.sleep(0.1)
    print(f"\n  ✅ {cantidad} paquetes de escaneo enviados")

def sql_injection():
    print("\n💉 Simulando SQL Injection...")
    ip = random.choice(ips_atacante)
    payloads = [
        "/?id=1' UNION SELECT 1,2,user()--",
        "/login.php?user=admin'--&pass=x",
        "/search?q=1' OR '1'='1",
        "/admin/../../../etc/passwd",
    ]
    for p in payloads:
        ts = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        log = f'web-srv01 apache2: {ip} - - [{ts}] "GET {p} HTTP/1.1" 403 512 "-" "sqlmap/1.7"'
        enviar_log(log)
        time.sleep(0.3)
    print(f"\n  ✅ Intentos de SQL Injection enviados")

print("""
╔══════════════════════════════════════╗
║     SOC-ELK Log Generator v1.0      ║
╚══════════════════════════════════════╝
""")

print("Selecciona el escenario:")
print("  1 - Brute Force SSH")
print("  2 - Port Scan")
print("  3 - SQL Injection")
print("  4 - Todos")

opcion = input("\nOpción: ")

if opcion == "1":
    brute_force()
elif opcion == "2":
    port_scan()
elif opcion == "3":
    sql_injection()
elif opcion == "4":
    brute_force()
    port_scan()
    sql_injection()
else:
    print("Opción no válida")

print("\n✅ Revisa Kibana en http://localhost:5601")
