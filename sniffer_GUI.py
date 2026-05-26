import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scapy.all import sniff, IP, Ether, TCP, UDP

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Network Sniffer v1.0")
        self.root.geometry("800x600")
        
        # Almacén de paquetes (Parte 2)
        self.paquetes = []
        self.sniffing = False

        # --- INTERFAZ (Parte 3) ---
        # Botones
        self.btn_frame = tk.Frame(root)
        self.btn_frame.pack(pady=10)
        
        self.start_btn = tk.Button(self.btn_frame, text="Iniciar Captura", command=self.start_sniffing, bg="green", fg="white")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(self.btn_frame, text="Detener", command=self.stop_sniffing, state=tk.DISABLED, bg="red", fg="white")
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Tabla de Paquetes
        self.tree = ttk.Treeview(root, columns=("ID", "Origen", "Destino", "Protocolo"), show='headings')
        self.tree.heading("ID", text="ID")
        self.tree.heading("Origen", text="IP Origen")
        self.tree.heading("Destino", text="IP Destino")
        self.tree.heading("Protocolo", text="Protocolo")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10)
        
        self.tree.bind("<Double-1>", self.mostrar_detalle) # Al hacer doble clic

        # Área de Detalle (Parte 1)
        self.detail_text = scrolledtext.ScrolledText(root, height=10)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def procesar_paquete(self, pkt):
        if pkt.haslayer(IP) and self.sniffing:
            self.paquetes.append(pkt)
            indice = len(self.paquetes) - 1
            # Insertar en la tabla de la GUI
            self.tree.insert("", tk.END, values=(indice, pkt[IP].src, pkt[IP].dst, pkt[IP].proto))

    def sniff_thread(self):
        sniff(prn=self.procesar_paquete, stop_filter=lambda x: not self.sniffing)

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        # Lanzar la captura en un hilo separado
        threading.Thread(target=self.sniff_thread, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def mostrar_detalle(self, event):
        item = self.tree.selection()[0]
        idx = int(self.tree.item(item, "values")[0])
        pkt = self.paquetes[idx]
        
        # Limpiar y mostrar detalle completo
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, pkt.show(dump=True))

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
