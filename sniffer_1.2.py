from scapy.all import sniff, IP, TCP, UDP, Ether

def analizar_detalle(pkt):
    print("\n" + "="*50)
    print("      ANÁLISIS DE PAQUETE CAPTURADO")
    print("="*50)

    # --- CAPA 2: ETHERNET (FRAME) ---
    if pkt.haslayer(Ether):
        print(f"\n[+] FRAME ETHERNET:")
        print(f"    - MAC Origen:  {pkt[Ether].src}")
        print(f"    - MAC Destino: {pkt[Ether].dst}")
        print(f"    - Tipo (EtherType): {hex(pkt[Ether].type)}")

    # --- CAPA 3: IP (DATAGRAMA) ---
    if pkt.haslayer(IP):
        print(f"\n[+] DATAGRAMA IP:")
        print(f"    - IP Origen:  {pkt[IP].src}")
        print(f"    - IP Destino: {pkt[IP].dst}")
        print(f"    - Versión:    {pkt[IP].version}")
        print(f"    - TTL:        {pkt[IP].ttl}")
        print(f"    - Protocolo:  {pkt[IP].proto}")

    # --- CAPA 4: TRANSPORTE (SEGMENTO) ---
    if pkt.haslayer(TCP):
        print(f"\n[+] SEGMENTO TCP:")
        print(f"    - Puerto Origen:  {pkt[TCP].sport}")
        print(f"    - Puerto Destino: {pkt[TCP].dport}")
        print(f"    - Flags:          {pkt[TCP].flags}")
    
    elif pkt.haslayer(UDP):
        print(f"\n[+] DATAGRAMA UDP:")
        print(f"    - Puerto Origen:  {pkt[UDP].sport}")
        print(f"    - Puerto Destino: {pkt[UDP].dport}")
        print(f"    - Longitud:       {pkt[UDP].len}")

    print("\n" + "="*50)

print("Esperando un paquete para análisis detallado...")
# Capturamos solo 1 paquete que tenga IP
sniff(filter="ip", prn=analizar_detalle, count=1)
