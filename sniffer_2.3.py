#-------------------------------------------------------------------------------------------
#--- Se importan las librerías necesarias para que el sniffer funcione                   ---
#-------------------------------------------------------------------------------------------
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import logging
import io
from contextlib import redirect_stdout
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, conf, get_if_list

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("---- Sniffer Versión Beta ----")
        self.root.geometry("1100x850")
        self.root.configure(bg="#f5f6fa")
        
        self.paquetes = []
        self.sniffing = False

        #-------------------------------------------------------------------------------------------
        #--- Panel de control                                                                    ---
        #-------------------------------------------------------------------------------------------

        self.ctrl_frame = tk.Frame(root, pady=15, bg="#2f3640")
        self.ctrl_frame.pack(fill=tk.X)

        self.start_btn = tk.Button(self.ctrl_frame, text="▶ INICIAR CAPTURA", command=self.start_sniffing, 
                                   bg="#44bd32", fg="white", width=18, font=('Segoe UI', 10, 'bold'))
        self.start_btn.pack(side=tk.LEFT, padx=15)
        
        self.stop_btn = tk.Button(self.ctrl_frame, text="■ DETENER", command=self.stop_sniffing, 
                                  state=tk.DISABLED, bg="#c23616", fg="white", width=12, font=('Segoe UI', 10, 'bold'))
        self.stop_btn.pack(side=tk.LEFT)

        self.clear_btn = tk.Button(self.ctrl_frame, text="🗑 LIMPIAR", command=self.limpiar_tabla, 
                                   bg="#718093", fg="white", width=12, font=('Segoe UI', 10, 'bold'))
        self.clear_btn.pack(side=tk.LEFT, padx=15)

        tk.Label(self.ctrl_frame, text="FILTRO:", bg="#2f3640", fg="white", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(20, 5))
        self.filter_var = tk.StringVar(value="TODOS")
        self.filter_menu = ttk.Combobox(self.ctrl_frame, textvariable=self.filter_var, 
                                        values=["TODOS", "TCP", "UDP", "ICMP"], state="readonly", width=10)
        self.filter_menu.pack(side=tk.LEFT)

        #-------------------------------------------------------------------------------------------
        #--- Tabla (para capa 1 y 3)                                                             ---
        #-------------------------------------------------------------------------------------------

        self.tree_frame = tk.Frame(root)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        columns = ("ID", "MAC Origen", "MAC Destino", "IP Origen", "IP Destino", "Protocolo")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show='headings')
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor=tk.CENTER)

        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.mostrar_detalle)

        #-------------------------------------------------------------------------------------------
        #--- Visor de interpretación                                                             ---
        #-------------------------------------------------------------------------------------------

        tk.Label(root, text="INTERPRETACIÓN DE CAMPOS (FRAME Y DATAGRAMA):", bg="#f5f6fa", font=('Segoe UI', 11, 'bold')).pack(anchor=tk.W, padx=15)
        self.detail_text = scrolledtext.ScrolledText(root, height=18, bg="#1e1e1e", fg="#dcdde1", font=('Consolas', 11))
        self.detail_text.pack(fill=tk.BOTH, padx=15, pady=10)

    def filtrar_paquete(self, pkt):
        f = self.filter_var.get()
        if f == "TODOS": return True
        if f == "TCP" and pkt.haslayer(TCP): return True
        if f == "UDP" and pkt.haslayer(UDP): return True
        if f == "ICMP" and pkt.haslayer(ICMP): return True
        return False

    def procesar_paquete(self, pkt):
        if self.sniffing:
            if self.filtrar_paquete(pkt):
                self.paquetes.append(pkt)
                idx = len(self.paquetes) - 1
                
                #-------------------------------------------------------------------------------------------
                #--- Capa 2 (Ethernet)                                                                   ---
                #-------------------------------------------------------------------------------------------

                mac_src = pkt[Ether].src if pkt.haslayer(Ether) else "FF:FF:FF:FF:FF:FF"
                mac_dst = pkt[Ether].dst if pkt.haslayer(Ether) else "FF:FF:FF:FF:FF:FF"
                
                #-------------------------------------------------------------------------------------------
                #--- Capa 3 (IP)                                                                         ---
                #-------------------------------------------------------------------------------------------
                ip_src = pkt[IP].src if pkt.haslayer(IP) else "---"
                ip_dst = pkt[IP].dst if pkt.haslayer(IP) else "---"
                
                proto = "Otro"
                if pkt.haslayer(TCP): proto = "TCP"
                elif pkt.haslayer(UDP): proto = "UDP"
                elif pkt.haslayer(ICMP): proto = "ICMP"

                self.root.after(0, lambda: self.tree.insert("", tk.END, values=(idx, mac_src, mac_dst, ip_src, ip_dst, proto)))

    def sniff_thread(self):
        try:
            conf.L3socket = conf.L3socket 
            sniff(prn=self.procesar_paquete, stop_filter=lambda x: not self.sniffing, store=0)
        except Exception as e:
            print(f"Error: {e}")

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.detail_text.insert(tk.END, "[*] Captura dinámica iniciada...\n")
        threading.Thread(target=self.sniff_thread, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def limpiar_tabla(self):
        self.paquetes = []
        for item in self.tree.get_children(): self.tree.delete(item)
        self.detail_text.delete(1.0, tk.END)

    def mostrar_detalle(self, event):
        seleccion = self.tree.selection()
        if not seleccion: return
        item = seleccion[0]
        idx = int(self.tree.item(item, "values")[0])
        pkt = self.paquetes[idx]

        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, f"=== ANÁLISIS DEL PAQUETE ID: {idx} ===\n\n")

        #-------------------------------------------------------------------------------------------
        #--- Interpretación de la capa 2 (Frame Ethernet)                                        ---
        #-------------------------------------------------------------------------------------------

        if pkt.haslayer(Ether):
            self.detail_text.insert(tk.END, "[ CAPA 2 - FRAME ETHERNET ]\n")
            self.detail_text.insert(tk.END, f"  > MAC Destino: {pkt[Ether].dst} (Dirección física del receptor)\n")
            self.detail_text.insert(tk.END, f"  > MAC Origen : {pkt[Ether].src} (Dirección física del emisor)\n")
            self.detail_text.insert(tk.END, f"  > Tipo: {hex(pkt[Ether].type)} (Protocolo encapsulado)\n\n")

        #-------------------------------------------------------------------------------------------
        #--- Interpretación de la capa 3 (Datagrama IPv4)                                        ---
        #-------------------------------------------------------------------------------------------

        if pkt.haslayer(IP):
            self.detail_text.insert(tk.END, "[ CAPA 3 - DATAGRAMA IP ]\n")
            self.detail_text.insert(tk.END, f"  > Versión: {pkt[IP].version} (IPv4)\n")
            self.detail_text.insert(tk.END, f"  > IHL: {pkt[IP].ihl * 4} bytes (Tamaño del encabezado)\n")
            self.detail_text.insert(tk.END, f"  > Tos: {pkt[IP].tos} (Tipo de Servicio)\n")
            self.detail_text.insert(tk.END, f"  > Longitud Total: {pkt[IP].len} bytes\n")
            self.detail_text.insert(tk.END, f"  > Identificación: {pkt[IP].id}\n")
            self.detail_text.insert(tk.END, f"  > Flags: {pkt[IP].flags} (Fragmentación)\n")
            self.detail_text.insert(tk.END, f"  > TTL: {pkt[IP].ttl} (Tiempo de vida en la red)\n")
            self.detail_text.insert(tk.END, f"  > Protocolo: {pkt[IP].proto} (ID del protocolo superior)\n")
            self.detail_text.insert(tk.END, f"  > Checksum: {hex(pkt[IP].chksum)}\n")
            self.detail_text.insert(tk.END, f"  > IP Origen: {pkt[IP].src}\n")
            self.detail_text.insert(tk.END, f"  > IP Destino: {pkt[IP].dst}\n\n")

        #-------------------------------------------------------------------------------------------
        #--- Interpretación de la capa 4 (Segmento TCP/UDP)                                      ---
        #-------------------------------------------------------------------------------------------

        if pkt.haslayer(TCP):
            self.detail_text.insert(tk.END, "[ CAPA 4 - SEGMENTO TCP ]\n")
            self.detail_text.insert(tk.END, f"  > Puerto Origen : {pkt[TCP].sport} (Puerto de la aplicación emisora)\n")
            self.detail_text.insert(tk.END, f"  > Puerto Destino: {pkt[TCP].dport} (Puerto de la aplicación receptora)\n")
            self.detail_text.insert(tk.END, f"  > Secuencia     : {pkt[TCP].seq}\n")
            self.detail_text.insert(tk.END, f"  > Acknowledgment: {pkt[TCP].ack}\n")
            self.detail_text.insert(tk.END, f"  > Flags         : {pkt[TCP].flags}\n\n")

        elif pkt.haslayer(UDP):
            self.detail_text.insert(tk.END, "[ CAPA 4 - DATAGRAMA UDP ]\n")
            self.detail_text.insert(tk.END, f"  > Puerto Origen : {pkt[UDP].sport}\n")
            self.detail_text.insert(tk.END, f"  > Puerto Destino: {pkt[UDP].dport}\n")
            self.detail_text.insert(tk.END, f"  > Longitud      : {pkt[UDP].len} bytes\n\n")

        #-------------------------------------------------------------------------------------------
        #--- Volcado completo (RAW DATA)                                                         ---
        #-------------------------------------------------------------------------------------------
        self.detail_text.insert(tk.END, "[ ESTRUCTURA BINARIA COMPLETA ]\n")
        f = io.StringIO()
        with redirect_stdout(f): pkt.show()
        self.detail_text.insert(tk.END, f.getvalue())

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()