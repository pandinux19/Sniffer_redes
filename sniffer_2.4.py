#-------------------------------------------------------------------------------------------
#--- Se importan las librerías necesarias para que el sniffer funcione                   ---
#-------------------------------------------------------------------------------------------
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import logging
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Ether, conf

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📁 Analizador de Paquetes de Red - CUCEI UI")
        self.root.geometry("1300x850")
        self.root.configure(bg="#1e1e24")
        
        self.paquetes = []
        self.sniffing = False
        
        # Diccionario maestro de explicaciones técnicas para el Inspector de información
        self.diccionario_campos = self.inicializar_diccionario()

        #-------------------------------------------------------------------------------------------
        #--- Estilos UI (Modern Dark Theme)                                                      ---
        #-------------------------------------------------------------------------------------------
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", background="#1e1e24", foreground="#dcdde1")
        self.style.configure("Treeview", background="#2f3640", foreground="#f5f6fa", fieldbackground="#2f3640", borderwidth=0, font=('Segoe UI', 10))
        self.style.configure("Treeview.Heading", background="#3f4857", foreground="white", font=('Segoe UI', 10, 'bold'))
        self.style.map("Treeview", background=[('selected', '#4b7bec')])

        #-------------------------------------------------------------------------------------------
        #--- Panel de Control Superior                                                           ---
        #-------------------------------------------------------------------------------------------
        self.ctrl_frame = tk.Frame(root, pady=12, bg="#10141d")
        self.ctrl_frame.pack(fill=tk.X)

        self.start_btn = tk.Button(self.ctrl_frame, text="▶ INICIAR CAPTURA", command=self.start_sniffing, 
                                   bg="#44bd32", fg="white", activebackground="#4cd137", activeforeground="white",
                                   width=18, font=('Segoe UI', 10, 'bold'), relief=tk.FLAT)
        self.start_btn.pack(side=tk.LEFT, padx=15)
        
        self.stop_btn = tk.Button(self.ctrl_frame, text="■ DETENER", command=self.stop_sniffing, 
                                  state=tk.DISABLED, bg="#c23616", fg="white", activebackground="#e84118", activeforeground="white",
                                  width=12, font=('Segoe UI', 10, 'bold'), relief=tk.FLAT)
        self.stop_btn.pack(side=tk.LEFT)

        self.clear_btn = tk.Button(self.ctrl_frame, text="🗑 LIMPIAR", command=self.limpiar_tabla, 
                                   bg="#718093", fg="white", activebackground="#95a5a6", activeforeground="white",
                                   width=12, font=('Segoe UI', 10, 'bold'), relief=tk.FLAT)
        self.clear_btn.pack(side=tk.LEFT, padx=15)

        tk.Label(self.ctrl_frame, text="FILTRO:", bg="#10141d", fg="white", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(20, 5))
        self.filter_var = tk.StringVar(value="TODOS")
        self.filter_menu = ttk.Combobox(self.ctrl_frame, textvariable=self.filter_var, 
                                        values=["TODOS", "TCP", "UDP", "ICMP"], state="readonly", width=10)
        self.filter_menu.pack(side=tk.LEFT)

        #-------------------------------------------------------------------------------------------
        #--- Estructura de Paneles Divididos                                                     ---
        #-------------------------------------------------------------------------------------------
        self.main_splitter = tk.PanedWindow(root, orient=tk.HORIZONTAL, bg="#1e1e24", sashwidth=6)
        self.main_splitter.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.right_splitter = tk.PanedWindow(orient=tk.VERTICAL, bg="#1e1e24", sashwidth=6)

        #--- PANEL IZQUIERDO: Lista de Paquetes ---
        self.left_container = tk.Frame(self.main_splitter, bg="#2f3640")
        
        columns = ("ID", "Protocolo", "IP Origen", "IP Destino")
        self.tree_lista = ttk.Treeview(self.left_container, columns=columns, show='headings')
        for col in columns:
            self.tree_lista.heading(col, text=col)
            self.tree_lista.column(col, width=110, anchor=tk.CENTER)
        self.tree_lista.column("ID", width=50)

        self.scroll_lista = ttk.Scrollbar(self.left_container, orient=tk.VERTICAL, command=self.tree_lista.yview)
        self.tree_lista.configure(yscroll=self.scroll_lista.set)
        
        self.tree_lista.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scroll_lista.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree_lista.bind("<<TreeviewSelect>>", self.cargar_capas_paquete)

        #--- PANEL DERECHO SUPERIOR: Árbol de Detalles Estructurado ---
        self.top_right_container = tk.LabelFrame(self.right_splitter, text=" Detalles del Datagrama (Estructura de Capas) ", 
                                                 bg="#232732", fg="#4b7bec", font=('Segoe UI', 10, 'bold'))
        
        self.tree_detalles = ttk.Treeview(self.top_right_container, columns=("Valor"), show='tree headings')
        self.tree_detalles.heading("#0", text="Campo / Segmento")
        self.tree_detalles.heading("Valor", text="Valor Interpretado")
        self.tree_detalles.column("#0", width=250, anchor=tk.W)
        self.tree_detalles.column("Valor", width=250, anchor=tk.W)

        self.scroll_detalles = ttk.Scrollbar(self.top_right_container, orient=tk.VERTICAL, command=self.tree_detalles.yview)
        self.tree_detalles.configure(yscroll=self.scroll_detalles.set)
        
        self.tree_detalles.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scroll_detalles.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree_detalles.bind("<<TreeviewSelect>>", self.inspeccionar_campo)

        #--- PANEL DERECHO INFERIOR: Inspector de Campos ---
        self.bottom_right_container = tk.LabelFrame(self.right_splitter, text=" Inspector de Campo / Información Detallada ", 
                                                    bg="#1a1c23", fg="#44bd32", font=('Segoe UI', 10, 'bold'))
        self.inspector_text = scrolledtext.ScrolledText(self.bottom_right_container, bg="#101216", fg="#dcdde1", 
                                                        font=('Consolas', 11), wrap=tk.WORD, borderwidth=0)
        self.inspector_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.main_splitter.add(self.left_container, minsize=450)
        self.main_splitter.add(self.right_splitter, minsize=550)
        
        self.right_splitter.add(self.top_right_container, minsize=350)
        self.right_splitter.add(self.bottom_right_container, minsize=250)

    #-------------------------------------------------------------------------------------------
    #--- Lógica de Captura y Filtrado                                                        ---
    #-------------------------------------------------------------------------------------------
    def filtrar_paquete(self, pkt):
        f = self.filter_var.get()
        if f == "TODOS": return True
        if f == "TCP" and pkt.haslayer(TCP): return True
        if f == "UDP" and pkt.haslayer(UDP): return True
        if f == "ICMP" and (pkt.haslayer(ICMP) or (pkt.haslayer(IPv6) and pkt[IPv6].nh == 58)): return True
        return False

    def procesar_paquete(self, pkt):
        if self.sniffing and self.filtrar_paquete(pkt):
            self.paquetes.append(pkt)
            idx = len(self.paquetes) - 1
            
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                ip_src = pkt[IPv6].src
                ip_dst = pkt[IPv6].dst
            else:
                ip_src = "---"
                ip_dst = "---"
            
            proto = "Otro"
            if pkt.haslayer(TCP): proto = "TCP"
            elif pkt.haslayer(UDP): proto = "UDP"
            elif pkt.haslayer(ICMP): proto = "ICMP"
            elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 58: proto = "ICMPv6"

            self.root.after(0, lambda: self.tree_lista.insert("", tk.END, values=(idx, proto, ip_src, ip_dst)))

    def sniff_thread(self):
        try:
            conf.L3socket = conf.L3socket 
            sniff(prn=self.procesar_paquete, stop_filter=lambda x: not self.sniffing, store=0)
        except Exception as e:
            print(f"Error en captura: {e}")

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.inspector_text.insert(tk.END, "[*] Captura dinámica iniciada...\n")
        threading.Thread(target=self.sniff_thread, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def limpiar_tabla(self):
        self.paquetes = []
        for item in self.tree_lista.get_children(): self.tree_lista.delete(item)
        for item in self.tree_detalles.get_children(): self.tree_detalles.delete(item)
        self.inspector_text.delete(1.0, tk.END)

    #-------------------------------------------------------------------------------------------
    #--- Lógica del Árbol de Capas                                                           ---
    #-------------------------------------------------------------------------------------------
    def cargar_capas_paquete(self, event):
        seleccion = self.tree_lista.selection()
        if not seleccion: return
        
        for item in self.tree_detalles.get_children(): 
            self.tree_detalles.delete(item)
            
        idx = int(self.tree_lista.item(seleccion[0], "values")[0])
        pkt = self.paquetes[idx]

        # --- Capa 2: Ethernet ---
        if pkt.haslayer(Ether):
            l2_root = self.tree_detalles.insert("", tk.END, text="Capa 2 - Frame Ethernet", values=("",), open=True)
            self.tree_detalles.insert(l2_root, tk.END, text="MAC Origen", values=(pkt[Ether].src,))
            self.tree_detalles.insert(l2_root, tk.END, text="MAC Destino", values=(pkt[Ether].dst,))
            self.tree_detalles.insert(l2_root, tk.END, text="Tipo Protocolo", values=(hex(pkt[Ether].type),))

        # --- Capa 3: IP (v4 / v6) ---
        if pkt.haslayer(IP):
            l3_root = self.tree_detalles.insert("", tk.END, text="Capa 3 - Datagrama IPv4", values=("",), open=True)
            self.tree_detalles.insert(l3_root, tk.END, text="Versión", values=(pkt[IP].version,))
            self.tree_detalles.insert(l3_root, tk.END, text="IHL (Header Length)", values=(f"{pkt[IP].ihl * 4} bytes",))
            self.tree_detalles.insert(l3_root, tk.END, text="Tipo de Servicio (ToS)", values=(pkt[IP].tos,))
            self.tree_detalles.insert(l3_root, tk.END, text="Longitud Total", values=(f"{pkt[IP].len} bytes",))
            self.tree_detalles.insert(l3_root, tk.END, text="Identificación ID", values=(pkt[IP].id,))
            self.tree_detalles.insert(l3_root, tk.END, text="Flags IP", values=(str(pkt[IP].flags),))
            self.tree_detalles.insert(l3_root, tk.END, text="Fragment Offset", values=(pkt[IP].frag,))
            self.tree_detalles.insert(l3_root, tk.END, text="TTL (Time To Live)", values=(pkt[IP].ttl,))
            self.tree_detalles.insert(l3_root, tk.END, text="Protocolo Superior", values=(pkt[IP].proto,))
            self.tree_detalles.insert(l3_root, tk.END, text="Checksum IP", values=(hex(pkt[IP].chksum),))
            self.tree_detalles.insert(l3_root, tk.END, text="IP Origen", values=(pkt[IP].src,))
            self.tree_detalles.insert(l3_root, tk.END, text="IP Destino", values=(pkt[IP].dst,))

        elif pkt.haslayer(IPv6):
            l3_root = self.tree_detalles.insert("", tk.END, text="Capa 3 - Datagrama IPv6", values=("",), open=True)
            self.tree_detalles.insert(l3_root, tk.END, text="Versión", values=(pkt[IPv6].version,))
            self.tree_detalles.insert(l3_root, tk.END, text="Clase de Tráfico (tc)", values=(pkt[IPv6].tc,))
            self.tree_detalles.insert(l3_root, tk.END, text="Etiqueta de Flujo (fl)", values=(pkt[IPv6].fl,))
            self.tree_detalles.insert(l3_root, tk.END, text="Longitud de Carga (plen)", values=(f"{pkt[IPv6].plen} bytes",))
            self.tree_detalles.insert(l3_root, tk.END, text="Siguiente Encabezado (nh)", values=(pkt[IPv6].nh,))
            self.tree_detalles.insert(l3_root, tk.END, text="Límite de Saltos (hlim)", values=(pkt[IPv6].hlim,))
            self.tree_detalles.insert(l3_root, tk.END, text="IP Origen v6", values=(pkt[IPv6].src,))
            self.tree_detalles.insert(l3_root, tk.END, text="IP Destino v6", values=(pkt[IPv6].dst,))

        # --- Capa 4: Transporte ---
        if pkt.haslayer(TCP):
            l4_root = self.tree_detalles.insert("", tk.END, text="Capa 4 - Segmento TCP", values=("",), open=True)
            self.tree_detalles.insert(l4_root, tk.END, text="Puerto Origen", values=(pkt[TCP].sport,))
            self.tree_detalles.insert(l4_root, tk.END, text="Puerto Destino", values=(pkt[TCP].dport,))
            self.tree_detalles.insert(l4_root, tk.END, text="Número de Secuencia", values=(pkt[TCP].seq,))
            self.tree_detalles.insert(l4_root, tk.END, text="Acknowledgment (ACK Num)", values=(pkt[TCP].ack,))
            self.tree_detalles.insert(l4_root, tk.END, text="Data Offset", values=(pkt[TCP].dataofs,))
            self.tree_detalles.insert(l4_root, tk.END, text="Flags TCP", values=(str(pkt[TCP].flags),))
            self.tree_detalles.insert(l4_root, tk.END, text="Ventana (Window Size)", values=(pkt[TCP].window,))
            self.tree_detalles.insert(l4_root, tk.END, text="Checksum TCP", values=(hex(pkt[TCP].chksum),))
            self.tree_detalles.insert(l4_root, tk.END, text="Urg Pointer", values=(pkt[TCP].urgptr,))
            
        elif pkt.haslayer(UDP):
            l4_root = self.tree_detalles.insert("", tk.END, text="Capa 4 - Datagrama UDP", values=("",), open=True)
            self.tree_detalles.insert(l4_root, tk.END, text="Puerto Origen", values=(pkt[UDP].sport,))
            self.tree_detalles.insert(l4_root, tk.END, text="Puerto Destino", values=(pkt[UDP].dport,))
            self.tree_detalles.insert(l4_root, tk.END, text="Longitud UDP", values=(f"{pkt[UDP].len} bytes",))
            self.tree_detalles.insert(l4_root, tk.END, text="Checksum UDP", values=(hex(pkt[UDP].chksum),))

    #-------------------------------------------------------------------------------------------
    #--- Lógica del Inspector Explicativo                                                    ---
    #-------------------------------------------------------------------------------------------
    def inspeccionar_campo(self, event):
        seleccion = self.tree_detalles.selection()
        if not seleccion: return
        
        item = seleccion[0]
        nombre_campo = self.tree_detalles.item(item, "text")
        valores = self.tree_detalles.item(item, "values")
        valor_campo = valores[0] if valores else ""

        self.inspector_text.delete(1.0, tk.END)
        
        if nombre_campo in self.diccionario_campos:
            info = self.diccionario_campos[nombre_campo]
            self.inspector_text.insert(tk.END, f"🔍 CAMPO SELECCIONADO: {nombre_campo.upper()}\n")
            if valor_campo:
                self.inspector_text.insert(tk.END, f"» Valor en este paquete: {valor_campo}\n\n")
            self.inspector_text.insert(tk.END, f"📋 EXPLICACIÓN DE REDES:\n{info}\n")
        else:
            self.inspector_text.insert(tk.END, f"📦 SECCIÓN: {nombre_campo}\n\n")
            self.inspector_text.insert(tk.END, "Despliega este nodo para obtener los campos individuales mapeados de forma limpia.")

    def inicializar_diccionario(self):
        return {
            "MAC Origen": "Dirección física (Hardware) única de la tarjeta de red del emisor.",
            "MAC Destino": "Dirección física de destino en la red local. Puede ser Broadcast (FF:FF:FF:FF:FF:FF) si va a todos.",
            "Tipo Protocolo": "Indica el protocolo de capa superior (ej. 0x0800 avisa que el cuerpo contiene un datagrama IPv4, 0x86dd para IPv6).",
            "Versión": "Especifica el formato del encabezado IP (v4 o v6).",
            "IHL (Header Length)": "Internet Header Length. Longitud del encabezado de la capa IP. El valor mínimo estándar es de 20 bytes.",
            "Tipo de Servicio (ToS)": "Define parámetros de prioridad y calidad de servicio (QoS) para el manejo de este paquete en la red.",
            "Longitud Total": "Mide el tamaño completo del paquete actual: incluye este encabezado IP más la carga útil (transporte/datos).",
            "Identificación ID": "Número de serie asignado al paquete. Ayuda a los equipos de red a reensamblar fragmentos si el paquete fue dividido.",
            "Flags IP": "Indicadores de fragmentación:\n• DF (Don't Fragment): Si es 1, impide dividir el paquete.\n• MF (More Fragments): Si es 1, quedan más fragmentos por recibir.",
            "TTL (Time To Live)": "Tiempo de vida del paquete. Cada router por el que pasa le resta 1. Si llega a cero, el paquete se descarta, previniendo bucles infinitos.",
            "Protocolo Superior": "Identifica el protocolo de la siguiente capa (Transporte). Valores comunes: 6 para TCP, 17 para UDP, 1 para ICMP.",
            "Checksum IP": "Suma de verificación usada para asegurar que los datos del encabezado IP no se hayan corrompido en el trayecto.",
            "IP Origen": "Dirección lógica de red de la computadora que emitió originalmente el mensaje.",
            "IP Destino": "Dirección lógica de destino hacia donde los routers deben enrutar este paquete.",
            "Puerto Origen": "Puerto de la aplicación local que abrió la sesión para transmitir la información.",
            "Puerto Destino": "Puerto del servicio remoto solicitado (ej: Puerto 80 para servidores web HTTP, 443 para HTTPS).",
            "Número de Secuencia": "Contador de bytes que usa TCP para asegurar que los fragmentos de información se junten en el orden correcto.",
            "Acknowledgment (ACK Num)": "Número de acuse de recibo. Le indica al emisor qué byte espera recibir a continuación.",
            "Flags TCP": "Bits de control de conexión:\n• SYN: Iniciar enlace.\n• ACK: Confirmación de paquete recibido.\n• FIN: Solicitar cierre de enlace.\n• PSH: Forzar envío de datos.",
            "Ventana (Window Size)": "Indica la cantidad de bytes que el receptor está dispuesto a aceptar en su memoria intermedia antes de saturarse.",
            "Checksum TCP": "Algoritmo de control que valida la integridad total de los datos del segmento de transporte.",
            "Longitud UDP": "Especifica el tamaño total en bytes del datagrama UDP (su encabezado más sus datos adjuntos).",
            "Checksum UDP": "Código detector de errores encargado de validar que el datagrama UDP no sufriera alteraciones.",
            "IP Origen v6": "Dirección lógica de 128 bits escrita en formato hexadecimal que identifica al dispositivo emisor usando el protocolo IPv6.",
            "IP Destino v6": "Dirección de destino final de 128 bits para el ruteo global en arquitecturas de red IPv6.",
            "Clase de Tráfico (tc)": "Campo de IPv6 equivalente al ToS de IPv4. Se utiliza para priorizar paquetes en mecanismos de calidad de servicio (QoS).",
            "Etiqueta de Flujo (fl)": "Mantiene el ruteo continuo y ordenado de paquetes pertenecientes a un mismo flujo de comunicación en routers en tiempo real.",
            "Longitud de Carga (plen)": "Especifica el tamaño en bytes de la carga útil del paquete IPv6, es decir, todo lo que viene después del encabezado principal de 40 bytes.",
            "Siguiente Encabezado (nh)": "Determina el tipo de encabezado que sigue inmediatamente al de IPv6 (por ejemplo: 6 para TCP, 17 para UDP).",
            "Límite de Saltos (hlim)": "Equivalente al TTL en IPv4. Define el número máximo de saltos por routers que puede realizar el paquete antes de descartarse.",
            "Data Offset": "Indica el tamaño del encabezado TCP expresado en palabras de 32 bits, informando dónde empiezan exactamente los datos de la aplicación.",
            "Urg Pointer": "Puntero de urgencia TCP. Si el flag URG está encendido, este campo indica la posición de los datos prioritarios que deben procesarse inmediatamente.",
            "Fragment Offset": "Indica la posición exacta de este fragmento de datos con respecto al paquete IP original, permitiendo un reensamblado secuencial."
        }

#-------------------------------------------------------------------------------------------
#--- Bloque de ejecución principal (Completamente fuera de la clase)                     ---
#-------------------------------------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()