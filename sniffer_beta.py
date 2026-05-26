import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sniffer Python v.beta")
        self.root.geometry("900x700")
        
        self.paquetes = []
        self.sniffing = False

        # --- PANEL DE CONTROL (Superior) ---
        self.ctrl_frame = tk.Frame(root, pady=10)
        self.ctrl_frame.pack(fill=tk.X)

        self.start_btn = tk.Button(self.ctrl_frame, text="▶ Iniciar", command=self.start_sniffing, bg="#2ecc71", fg="white", width=10)
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(self.ctrl_frame, text="■ Detener", command=self.stop_sniffing, state=tk.DISABLED, bg="#e74c3c", fg="white", width=10)
        self.stop_btn.pack(side=tk.LEFT)

        tk.Label(self.ctrl_frame, text="Filtrar por:").pack(side=tk.LEFT, padx=(20, 5))
        self.filter_var = tk.StringVar(value="TODOS")
        self.filter_menu = ttk.Combobox(self.ctrl_frame, textvariable=self.filter_var, values=["TODOS", "TCP", "UDP", "ICMP"], state="readonly", width=10)
        self.filter_menu.pack(side=tk.LEFT)

        # --- TABLA DE PAQUETES ---
        self.tree = ttk.Treeview(root, columns=("ID", "Origen", "Destino", "Protocolo", "Puerto"), show='headings')
        self.tree.heading("ID", text="ID")
        self.tree.heading("Origen", text="IP Origen")
        self.tree.heading("Destino", text="IP Destino")
        self.tree.heading("Protocolo", text="Protocolo")
        self.tree.heading("Puerto", text="Puerto Dst")
        
        self.tree.column("ID", width=50, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10)
        self.tree.bind("<Double-1>", self.mostrar_detalle)

        # --- DETALLE DEL PAQUETE ---
        self.detail_text = scrolledtext.ScrolledText(root, height=12, bg="#2c3e50", fg="#ecf0f1", font=("Courier", 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def filtrar_paquete(self, pkt):
        filtro = self.filter_var.get()
        if filtro == "TODOS": return True
        if filtro == "TCP" and pkt.haslayer(TCP): return True
        if filtro == "UDP" and pkt.haslayer(UDP): return True
        if filtro == "ICMP" and pkt.haslayer(ICMP): return True
        return False

    def procesar_paquete(self, pkt):
        if pkt.haslayer(IP) and self.sniffing:
            if self.filtrar_paquete(pkt):
                self.paquetes.append(pkt)
                idx = len(self.paquetes) - 1
                
                # Extraer puerto si existe
                puerto = ""
                if pkt.haslayer(TCP): puerto = pkt[TCP].dport
                elif pkt.haslayer(UDP): puerto = pkt[UDP].dport
                
                # Insertar en la tabla
                self.tree.insert("", tk.END, values=(idx, pkt[IP].src, pkt[IP].dst, pkt[IP].proto, puerto))

    def sniff_thread(self):
        sniff(prn=self.procesar_paquete, stop_filter=lambda x: not self.sniffing, store=0)

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        threading.Thread(target=self.sniff_thread, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def mostrar_detalle(self, event):
        seleccion = self.tree.selection()
        if not seleccion: return
        item = seleccion[0]
        idx = int(self.tree.item(item, "values")[0])
        pkt = self.paquetes[idx]
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, pkt.show(dump=True))

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
