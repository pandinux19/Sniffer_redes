from scapy.all import sniff, IP, Ether

# 1. Lista para guardar los paquetes capturados
almacen_paquetes = []

def callback_sniff(pkt):
    """Esta función se ejecuta por cada paquete capturado"""
    if pkt.haslayer(IP):
        # Guardamos el paquete en nuestra lista
        almacen_paquetes.append(pkt)
        
        #resumen rápido en consola (Captura Dinámica)
        num = len(almacen_paquetes) - 1
        print(f"[{num}] {pkt[IP].src} --> {pkt[IP].dst} | Protocolo: {pkt[IP].proto}")

print("--- INICIANDO CAPTURA DINÁMICA ---")
print("Capturando 10 paquetes (o presiona Ctrl+C)...")

try:
    # Captura de una tanda de 10 paquetes para probar
    sniff(prn=callback_sniff, count=10, filter="ip")
except KeyboardInterrupt:
    pass

print("\n--- CAPTURA DETENIDA ---")

# 2. Menú de selección (Parte 2 y 3 básica)
if almacen_paquetes:
    try:
        opcion = int(input(f"\nElige un paquete para analizar (0 - {len(almacen_paquetes)-1}): "))
        paquete_elegido = almacen_paquetes[opcion]
        
        print("\n" + "="*40)
        print(f" ANALIZANDO PAQUETE NÚMERO {opcion}")
        print("="*40)
        
        paquete_elegido.show() 
        
    except (ValueError, IndexError):
        print("Opción no válida.")
else:
    print("No se capturaron paquetes.")
