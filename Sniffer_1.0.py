from scapy.all import sniff

def procesar_paquete(pkt):
    if pkt.haslayer("IP"):
        print(f"Nueva captura: {pkt['IP'].src} -> {pkt['IP'].dst} | Protocolo: {pkt['IP'].proto}")

print("Iniciando captura... (Presiona Ctrl+C para detener)")
# Capturamos 5 paquetes de prueba
sniff(prn=procesar_paquete, count=5)
