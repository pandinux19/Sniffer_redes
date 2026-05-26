#-------------------------------------------------------------------------------------------
#--- Sniffer de Red Profesional - UI Rediseñada y Responsiva (Comercial/Moderna)         ---
#--- Interfaz: Dark terminal aesthetic con acentos neón, tipografía refinada             ---
#--- Versión Final: Captura total sin filtros (TCP, UDP, ICMP, ARP, IPv4, IPv6, MACs)   ---
#--- Optimización: Layout 100% responsivo adaptable a cualquier resolución de pantalla   ---
#-------------------------------------------------------------------------------------------
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import threading
import logging
import platform
import subprocess
import os
import re
import time
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Ether, ARP, conf
import netifaces
import psutil

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ============================================================
# --- Paleta de colores y tokens de diseño               ---
# ============================================================
COLORS = {
    # Backgrounds
    "bg_base":       "#080c10",
    "bg_surface":    "#0d1117",
    "bg_elevated":   "#141b24",
    "bg_card":       "#0f1923",
    "bg_hover":      "#1a2535",

    # Bordes
    "border_dim":    "#1e2d3d",
    "border_mid":    "#1f3a52",
    "border_glow":   "#00e5ff",

    # Texto
    "text_primary":  "#e8f4f8",
    "text_secondary":"#7fa8c0",
    "text_dim":      "#3d6070",
    "text_mono":     "#a8d8ea",

    # Acentos
    "accent_cyan":   "#00e5ff",
    "accent_green":  "#00ff88",
    "accent_amber":  "#ffab00",
    "accent_red":    "#ff3355",
    "accent_blue":   "#4d9fff",

    # Protocolo tags
    "proto_tcp":     "#00e5ff",
    "proto_udp":     "#00ff88",
    "proto_icmp":    "#ffab00",
    "proto_arp":     "#ff55ff", 
    "proto_other":   "#7fa8c0",
}


class AnimatedButton(tk.Canvas):
    def __init__(self, parent, text, command=None, color=None, width=150, height=34, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=COLORS["bg_surface"], highlightthickness=0, bd=0)
        self.command = command
        self.color = color or COLORS["accent_cyan"]
        self.text = text
        self.w = width
        self.h = height
        self._disabled = False
        self._draw(hover=False)
        self.bind("<Enter>",    lambda e: self._draw(hover=True)  if not self._disabled else None)
        self.bind("<Leave>",    lambda e: self._draw(hover=False) if not self._disabled else None)
        self.bind("<Button-1>", lambda e: self._click())

    def _draw(self, hover=False):
        self.delete("all")
        r = 4
        w, h = self.w, self.h
        bg = COLORS["bg_hover"] if hover else COLORS["bg_elevated"]
        bc = self.color if hover and not self._disabled else (COLORS["border_dim"] if self._disabled else COLORS["border_mid"])
        self.create_rectangle(1, 1, w-1, h-1, outline=bc, fill=bg, width=1)
        if not self._disabled:
            self.create_line(r, 1, w-r, 1, fill=bc if not hover else self.color, width=1)
        fc = self.color if not self._disabled else COLORS["text_dim"]
        self.create_text(w//2, h//2, text=self.text, fill=fc, font=("Consolas", 9, "bold"), anchor="center")

    def _click(self):
        if not self._disabled and self.command:
            self.command()

    def config_state(self, state):
        self._disabled = (state == tk.DISABLED)
        self._draw(hover=False)

    def configure(self, **kwargs):
        if "state" in kwargs:
            self.config_state(kwargs.pop("state"))
        super().configure(**kwargs)


class StatusBadge(tk.Canvas):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, width=12, height=12, bg=COLORS["bg_base"], highlightthickness=0, bd=0)
        self._active = False
        self._phase = 0
        self._draw()

    def _draw(self):
        self.delete("all")
        color = COLORS["accent_green"] if self._active else COLORS["text_dim"]
        if self._active:
            outer_r = 5 + int(self._phase * 1.5)
            alpha_colors = ["#004422", "#002211", "#001108"]
            if outer_r <= 6:
                self.create_oval(6-outer_r, 6-outer_r, 6+outer_r, 6+outer_r, outline=alpha_colors[min(outer_r-5, 2)], fill="")
        self.create_oval(3, 3, 9, 9, fill=color, outline="")

    def set_active(self, active):
        self._active = active
        if active:
            self._animate()
        else:
            self._phase = 0
            self._draw()

    def _animate(self):
        if not self._active:
            return
        self._phase = (self._phase + 1) % 4
        self._draw()
        self.after(400, self._animate)


class PacketCounter(tk.Frame):
    def __init__(self, parent, label, color, **kwargs):
        super().__init__(parent, bg=COLORS["bg_surface"], **kwargs)
        tk.Label(self, text=label, bg=COLORS["bg_surface"], fg=COLORS["text_secondary"], font=("Consolas", 8, "normal")).pack(anchor="w")
        self.count_var = tk.StringVar(value="0")
        tk.Label(self, textvariable=self.count_var, bg=COLORS["bg_surface"], fg=color, font=("Consolas", 16, "bold")).pack(anchor="w")
        self._count = 0

    def increment(self):
        self._count += 1
        self.count_var.set(str(self._count))

    def reset(self):
        self._count = 0
        self.count_var.set("0")


class SectionHeader(tk.Frame):
    def __init__(self, parent, title, icon="", accent=None, **kwargs):
        super().__init__(parent, bg=COLORS["bg_card"], **kwargs)
        accent = accent or COLORS["accent_cyan"]
        tk.Frame(self, bg=accent, width=2).pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        tk.Label(self, text=f"{icon}  {title}" if icon else title, bg=COLORS["bg_card"], fg=accent, font=("Consolas", 9, "bold")).pack(side=tk.LEFT, pady=6)
        line = tk.Frame(self, bg=COLORS["border_dim"], height=1)
        line.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)


class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Proyecto Final - Equipo 11 (Sniffer Global de Red)")
        self.root.configure(bg=COLORS["bg_base"])
        self.root.minsize(1024, 650) # Límitador mínimo para evitar colapsos visuales extremos

        # --- AJUSTE CLAVE: MAXIMIZAR AUTOMÁTICAMENTE DEPENDIENDO DEL S.O ---
        try:
            if platform.system() == "Linux" or platform.system() == "Darwin":
                self.root.attributes('-zoomed', True)
            else:
                self.root.state('zoomed')
        except:
            self.root.geometry("1280x750") # Fallback seguro por si falla la llamada nativa

        self.paquetes = []
        self.sniffing = False
        self.current_interface = None
        self.pkt_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Otro": 0}

        self.diccionario_campos = self.inicializar_diccionario()
        self._setup_styles()
        self._build_ui()

        self.refresh_interface()
        self.start_network_monitor()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=COLORS["bg_base"], foreground=COLORS["text_primary"], borderwidth=0)
        s.configure("Packets.Treeview", background=COLORS["bg_card"], foreground=COLORS["text_primary"], fieldbackground=COLORS["bg_card"], borderwidth=0, rowheight=24, font=("Consolas", 9))
        s.configure("Packets.Treeview.Heading", background=COLORS["bg_elevated"], foreground=COLORS["accent_cyan"], font=("Consolas", 9, "bold"), relief="flat", borderwidth=0)
        s.map("Packets.Treeview", background=[("selected", COLORS["bg_hover"])], foreground=[("selected", COLORS["accent_cyan"])])
        s.configure("Details.Treeview", background=COLORS["bg_surface"], foreground=COLORS["text_mono"], fieldbackground=COLORS["bg_surface"], borderwidth=0, rowheight=22, font=("Consolas", 9))
        s.configure("Details.Treeview.Heading", background=COLORS["bg_elevated"], foreground=COLORS["accent_green"], font=("Consolas", 9, "bold"), relief="flat")
        s.map("Details.Treeview", background=[("selected", COLORS["bg_hover"])], foreground=[("selected", COLORS["accent_green"])])
        s.configure("Dark.Vertical.TScrollbar", background=COLORS["bg_elevated"], troughcolor=COLORS["bg_card"], borderwidth=0, arrowsize=10)
        s.configure("Dark.TSeparator", background=COLORS["border_dim"])

    def _build_ui(self):
        # Configuramos la raíz (root) como un grid dinámico escalable
        self.root.rowconfigure(4, weight=1) # El contenedor de paneles principales tomará todo el espacio restante
        self.root.columnconfigure(0, weight=1)

        self._build_titlebar()
        self._build_toolbar()
        self._build_stats_bar()
        self._build_network_bar()
        self._build_main_panels()
        self._build_statusbar()

    def _build_titlebar(self):
        bar = tk.Frame(self.root, bg=COLORS["bg_base"], height=40)
        bar.grid(row=0, column=0, sticky="ew")
        bar.pack_propagate(False)
        
        tk.Label(bar, text="◈", bg=COLORS["bg_base"], fg=COLORS["accent_cyan"], font=("Consolas", 14)).pack(side=tk.LEFT, padx=(15, 4))
        tk.Label(bar, text="EQUIPO 11", bg=COLORS["bg_base"], fg=COLORS["text_primary"], font=("Consolas", 12, "bold")).pack(side=tk.LEFT)
        tk.Label(bar, text="  //  Sniffer Promiscuo Global (Sin Filtros)", bg=COLORS["bg_base"], fg=COLORS["text_dim"], font=("Consolas", 9)).pack(side=tk.LEFT, padx=4)

        right = tk.Frame(bar, bg=COLORS["bg_base"])
        right.pack(side=tk.RIGHT, padx=15)
        self.status_badge = StatusBadge(right)
        self.status_badge.pack(side=tk.LEFT, padx=(0, 6))
        self.status_label_top = tk.Label(right, text="INACTIVO", bg=COLORS["bg_base"], fg=COLORS["text_dim"], font=("Consolas", 9, "bold"))
        self.status_label_top.pack(side=tk.LEFT)
        
        tk.Frame(self.root, bg=COLORS["border_dim"], height=1).grid(row=1, column=0, sticky="ew")

    def _build_toolbar(self):
        bar = tk.Frame(self.root, bg=COLORS["bg_surface"], pady=6, padx=15)
        bar.grid(row=2, column=0, sticky="ew")

        self.start_btn = AnimatedButton(bar, "▶  INICIAR CAPTURA", command=self.start_sniffing, color=COLORS["accent_green"], width=150, height=32)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = AnimatedButton(bar, "■  DETENER", command=self.stop_sniffing, color=COLORS["accent_red"], width=120, height=32)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.stop_btn.config_state(tk.DISABLED)

        self.clear_btn = AnimatedButton(bar, "⊘  LIMPIAR DATOS", command=self.limpiar_tabla, color=COLORS["accent_amber"], width=130, height=32)
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 15))

        self.refresh_btn = AnimatedButton(bar, "↻  REFRESCAR RED", command=self.refresh_interface, color=COLORS["accent_blue"], width=150, height=32)
        self.refresh_btn.pack(side=tk.LEFT)

        tk.Frame(bar, bg=COLORS["border_dim"], width=1).pack(side=tk.LEFT, fill=tk.Y, padx=15, pady=2)
        self.iface_toolbar_label = tk.Label(bar, text="INTERFAZ: --", bg=COLORS["bg_surface"], fg=COLORS["text_secondary"], font=("Consolas", 9))
        self.iface_toolbar_label.pack(side=tk.LEFT)

    def _build_stats_bar(self):
        bar = tk.Frame(self.root, bg=COLORS["bg_surface"], pady=6, padx=15)
        bar.grid(row=3, column=0, sticky="ew")

        self.counter_total = PacketCounter(bar, "TOTAL CAPTURADOS", COLORS["text_primary"])
        self.counter_total.pack(side=tk.LEFT, padx=(0, 20))
        tk.Frame(bar, bg=COLORS["border_dim"], width=1).pack(side=tk.LEFT, fill=tk.Y, pady=2, padx=(0, 20))

        self.counter_tcp   = PacketCounter(bar, "TCP",   COLORS["proto_tcp"])
        self.counter_tcp.pack(side=tk.LEFT, padx=(0, 20))
        self.counter_udp   = PacketCounter(bar, "UDP",   COLORS["proto_udp"])
        self.counter_udp.pack(side=tk.LEFT, padx=(0, 20))
        self.counter_icmp  = PacketCounter(bar, "ICMP/v6",  COLORS["proto_icmp"])
        self.counter_icmp.pack(side=tk.LEFT, padx=(0, 20))
        self.counter_arp   = PacketCounter(bar, "ARP",   COLORS["proto_arp"])
        self.counter_arp.pack(side=tk.LEFT, padx=(0, 20))
        self.counter_other = PacketCounter(bar, "OTROS", COLORS["proto_other"])
        self.counter_other.pack(side=tk.LEFT)

        self.time_label = tk.Label(bar, text="", bg=COLORS["bg_surface"], fg=COLORS["text_dim"], font=("Consolas", 8))
        self.time_label.pack(side=tk.RIGHT, padx=4)
        self._update_clock()

    def _build_network_bar(self):
        # Usamos Grid dinámico interno para la banda de información técnica
        bar = tk.Frame(self.root, bg=COLORS["bg_elevated"], pady=5, padx=15)
        bar.grid(row=4, column=0, sticky="ew")
        
        for i in range(6): bar.columnconfigure(i, weight=1)

        def net_grid_item(parent, key, col, color_val=None):
            f = tk.Frame(parent, bg=COLORS["bg_elevated"])
            f.grid(row=0, column=col, sticky="w")
            tk.Label(f, text=key, bg=COLORS["bg_elevated"], fg=COLORS["text_dim"], font=("Consolas", 8, "bold")).pack(side=tk.LEFT, padx=(0, 5))
            var = tk.StringVar(value="--")
            tk.Label(f, textvariable=var, bg=COLORS["bg_elevated"], fg=color_val or COLORS["text_primary"], font=("Consolas", 9)).pack(side=tk.LEFT)
            return var

        self.net_iface_var = net_grid_item(bar, "INTERFAZ", 0, COLORS["accent_cyan"])
        self.net_type_var  = net_grid_item(bar, "TIPO",     1, COLORS["text_secondary"])
        self.net_ipv4_var  = net_grid_item(bar, "IPv4",     2, COLORS["accent_green"])
        self.net_ipv6_var  = net_grid_item(bar, "IPv6",     3, COLORS["text_mono"])
        self.net_mac_var   = net_grid_item(bar, "MAC",      4, COLORS["text_secondary"])
        self.net_ssid_var  = net_grid_item(bar, "RED",      5, COLORS["accent_amber"])

    def _update_clock(self):
        self.time_label.config(text=time.strftime("  %Y-%m-%d  %H:%M:%S  "))
        self.root.after(1000, self._update_clock)

    def _build_main_panels(self):
        # Este contenedor ocupará todo el centro variable de la pantalla
        main = tk.Frame(self.root, bg=COLORS["bg_base"])
        main.grid(row=5, column=0, sticky="nsew") 
        self.root.rowconfigure(5, weight=1) # Le da el verdadero peso elástico vertical

        self.main_splitter = tk.PanedWindow(main, orient=tk.HORIZONTAL, bg=COLORS["bg_base"], sashwidth=4, sashrelief=tk.FLAT, sashpad=0)
        self.main_splitter.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 0))

        # --- PANEL IZQUIERDO ---
        left = tk.Frame(self.main_splitter, bg=COLORS["bg_card"])
        SectionHeader(left, "TRÁFICO INTERCEPTADO EN TIEMPO REAL", "⬡").pack(fill=tk.X)

        tree_frame = tk.Frame(left, bg=COLORS["bg_card"])
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ID", "Protocolo", "MAC Origen", "MAC Destino", "IP Origen", "IP Destino")
        self.tree_lista = ttk.Treeview(tree_frame, columns=columns, show="headings", style="Packets.Treeview", selectmode="browse")

        # Configuración elástica de anchos de columna (stretch=True)
        col_cfg = {
            "ID": (45, tk.CENTER), 
            "Protocolo": (75, tk.CENTER),
            "MAC Origen": (120, tk.W), 
            "MAC Destino": (120, tk.W),
            "IP Origen": (125, tk.W), 
            "IP Destino": (125, tk.W)
        }
        for col, (w, anchor) in col_cfg.items():
            self.tree_lista.heading(col, text=col)
            self.tree_lista.column(col, width=w, anchor=anchor, minwidth=w, stretch=True)

        self.tree_lista.tag_configure("TCP",  foreground=COLORS["proto_tcp"])
        self.tree_lista.tag_configure("UDP",  foreground=COLORS["proto_udp"])
        self.tree_lista.tag_configure("ICMP", foreground=COLORS["proto_icmp"])
        self.tree_lista.tag_configure("ICMPv6", foreground=COLORS["proto_icmp"])
        self.tree_lista.tag_configure("ARP",  foreground=COLORS["proto_arp"])
        self.tree_lista.tag_configure("Otro", foreground=COLORS["proto_other"])
        self.tree_lista.tag_configure("even", background=COLORS["bg_surface"])
        self.tree_lista.tag_configure("odd",  background=COLORS["bg_card"])

        scroll_v = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree_lista.yview, style="Dark.Vertical.TScrollbar")
        self.tree_lista.configure(yscroll=scroll_v.set)
        self.tree_lista.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_v.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_lista.bind("<<TreeviewSelect>>", self.cargar_capas_paquete)

        # --- PANEL DERECHO (SPLITTER VERTICAL RESPONSIVO) ---
        right = tk.PanedWindow(self.main_splitter, orient=tk.VERTICAL, bg=COLORS["bg_base"], sashwidth=4, sashrelief=tk.FLAT, sashpad=0)

        top_right = tk.Frame(right, bg=COLORS["bg_surface"])
        SectionHeader(top_right, "ESTRUCTURA COMPLETA DEL DATAGRAMA", "⬡", accent=COLORS["accent_green"]).pack(fill=tk.X)

        detail_frame = tk.Frame(top_right, bg=COLORS["bg_surface"])
        detail_frame.pack(fill=tk.BOTH, expand=True)

        self.tree_detalles = ttk.Treeview(detail_frame, columns=("Valor",), show="tree headings", style="Details.Treeview")
        self.tree_detalles.heading("#0",    text="CAMPO / SEGMENTO")
        self.tree_detalles.heading("Valor", text="VALOR INTERPRETADO")
        self.tree_detalles.column("#0",    width=200, anchor=tk.W, minwidth=140, stretch=True)
        self.tree_detalles.column("Valor", width=200, anchor=tk.W, minwidth=120, stretch=True)

        scroll_det = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.tree_detalles.yview, style="Dark.Vertical.TScrollbar")
        self.tree_detalles.configure(yscroll=scroll_det.set)
        self.tree_detalles.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_det.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_detalles.bind("<<TreeviewSelect>>", self.inspeccionar_campo)

        bottom_right = tk.Frame(right, bg=COLORS["bg_base"])
        SectionHeader(bottom_right, "INSPECTOR TEÓRICO DE CAMPO", "⬡", accent=COLORS["accent_amber"]).pack(fill=tk.X)

        self.inspector_text = tk.Text(bottom_right, bg=COLORS["bg_surface"], fg=COLORS["text_primary"], font=("Consolas", 9), wrap=tk.WORD, borderwidth=0, insertbackground=COLORS["accent_cyan"], selectbackground=COLORS["bg_hover"], relief="flat", padx=10, pady=8)
        self.inspector_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))

        self.inspector_text.tag_configure("header", foreground=COLORS["accent_amber"], font=("Consolas", 10, "bold"))
        self.inspector_text.tag_configure("value", foreground=COLORS["accent_cyan"], font=("Consolas", 9))
        self.inspector_text.tag_configure("label", foreground=COLORS["text_secondary"], font=("Consolas", 9, "bold"))
        self.inspector_text.tag_configure("body", foreground=COLORS["text_primary"], font=("Consolas", 9))
        self.inspector_text.tag_configure("dim", foreground=COLORS["text_dim"], font=("Consolas", 9))

        # Añadimos los elementos calculando pesos proporcionales (50% - 50%)
        self.main_splitter.add(left,  minsize=450, stretch="always")
        self.main_splitter.add(right, minsize=450, stretch="always")
        right.add(top_right,    minsize=220, stretch="always")
        right.add(bottom_right, minsize=160, stretch="always")

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=COLORS["bg_elevated"], pady=4, padx=12)
        bar.grid(row=6, column=0, sticky="ew")

        def stat_item(parent, key):
            f = tk.Frame(parent, bg=COLORS["bg_elevated"])
            f.pack(side=tk.LEFT, padx=6)
            tk.Label(f, text=key + ":", bg=COLORS["bg_elevated"], fg=COLORS["text_dim"], font=("Consolas", 8, "bold")).pack(side=tk.LEFT, padx=(0, 2))
            lbl_v = tk.Label(f, text="--", bg=COLORS["bg_elevated"], fg=COLORS["text_secondary"], font=("Consolas", 8))
            lbl_v.pack(side=tk.LEFT)
            return lbl_v

        self.lbl_conn  = stat_item(bar, "ESTADO")
        self.lbl_iface = stat_item(bar, "INTERFAZ")
        self.lbl_type  = stat_item(bar, "TIPO")
        self.lbl_ipv4  = stat_item(bar, "IPv4")
        self.lbl_ipv6  = stat_item(bar, "IPv6")
        self.lbl_mac   = stat_item(bar, "MAC")
        self.lbl_net   = stat_item(bar, "RED")

        for label in [self.lbl_conn, self.lbl_iface, self.lbl_type, self.lbl_ipv4, self.lbl_ipv6, self.lbl_mac]:
            tk.Label(label.master.master, text="│", bg=COLORS["bg_elevated"], fg=COLORS["border_mid"], font=("Consolas", 8)).pack(side=tk.LEFT)

        tk.Label(bar, text="v2.1.0 (PROMISCUO) // CUCEI", bg=COLORS["bg_elevated"], fg=COLORS["text_dim"], font=("Consolas", 8)).pack(side=tk.RIGHT)

    def _log(self, text, tag="body"):
        self.inspector_text.insert(tk.END, text, tag)

    def _log_info(self, msg):
        self.inspector_text.insert(tk.END, "\n  ", "dim")
        self.inspector_text.insert(tk.END, msg + "\n", "dim")

    def get_active_interface(self):
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                default_iface = gateways['default'][netifaces.AF_INET][1]
                if not any(v in default_iface.lower() for v in ['virtual', 'vbox', 'vmware', 'loopback']):
                    return default_iface
        except: pass
        for iface in netifaces.interfaces():
            if any(v in iface.lower() for v in ['virtual', 'vbox', 'vmware', 'loopback', 'lo']): continue
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    if not ip.startswith('169.254') and not ip.startswith('127.'): return iface
            except: continue
        return None

    def refresh_interface(self):
        if self.sniffing:
            r = messagebox.askyesno("Cambio de red", "La captura está activa. ¿Reiniciar con la nueva interfaz?")
            if r:
                self.stop_sniffing()
                self.current_interface = self.get_active_interface()
                if self.current_interface:
                    self.update_connection_status()
                    self.root.after(500, self.start_sniffing)
            else: self.update_connection_status()
        else:
            self.current_interface = self.get_active_interface()
            self.update_connection_status()

    def get_wifi_network_info(self):
        system = platform.system()
        ssid = channel = signal = None
        if system == "Windows":
            try:
                result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=3)
                lines = result.stdout.splitlines()
                for line in lines:
                    if "SSID" in line and "BSSID" not in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            ssid = parts[1].strip()
                            if ssid: break
                for line in lines:
                    if "Channel" in line:
                        parts = line.split(":")
                        if len(parts) > 1: channel = parts[1].strip()
                    if "Signal" in line:
                        parts = line.split(":")
                        if len(parts) > 1: signal = parts[1].strip()
            except: pass
        elif system == "Linux":
            try:
                iface = self.current_interface or "wlan0"
                result = subprocess.run(["iwconfig", iface], capture_output=True, text=True, timeout=3)
                for line in result.stdout.splitlines():
                    if "ESSID:" in line: ssid = line.split("ESSID:")[1].strip('"')
                    if "Frequency:" in line:
                        p = line.split("Frequency:")
                        if len(p) > 1: channel = p[1].split()[0]
                    if "Signal level=" in line:
                        p = line.split("Signal level=")
                        if len(p) > 1: signal = p[1].split()[0]
            except: pass
        return ssid, channel, signal

    def get_ethernet_network_info(self, iface_name):
        speed = duplex = None
        system = platform.system()
        if system == "Windows":
            try:
                cmd = f'powershell -command "Get-NetAdapter -Name \\"{iface_name}\\" | Select-Object Name, LinkSpeed"'
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3, shell=True)
                for line in result.stdout.splitlines():
                    if "LinkSpeed" in line:
                        parts = line.split(":")
                        if len(parts) > 1: speed = parts[1].strip()
            except: pass
        elif system == "Linux":
            try:
                sp = f"/sys/class/net/{iface_name}/speed"
                dp = f"/sys/class/net/{iface_name}/duplex"
                if os.path.exists(sp):
                    with open(sp) as f:
                        v = f.read().strip()
                        if v and v != "-1": speed = f"{v} Mbps"
                if os.path.exists(dp):
                    with open(dp) as f: duplex = f.read().strip()
            except: pass
        return speed, duplex

    def get_network_name(self):
        if not self.current_interface: return "No conectado"
        conn_type = self.detect_connection_type(self.current_interface)
        if "Wi-Fi" in conn_type:
            ssid, channel, signal = self.get_wifi_network_info()
            if ssid:
                info = ssid
                if channel: info += f"  ch.{channel}"
                if signal:  info += f"  sig:{signal}"
                return info
            return "Wi-Fi (SSID oculto)"
        elif "Ethernet" in conn_type:
            speed, duplex = self.get_ethernet_network_info(self.current_interface)
            info = "Ethernet"
            if speed:  info += f"  {speed}"
            if duplex: info += f"  {duplex}"
            return info
        return "Red desconocida"

    def get_interface_addresses(self, iface_name):
        ipv4 = None; ipv6_list = []; mac = None
        try:
            addrs = netifaces.ifaddresses(iface_name)
            if netifaces.AF_INET  in addrs: ipv4 = addrs[netifaces.AF_INET][0]['addr']
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    ipv6 = addr['addr'].split('%')[0]
                    if ipv6 not in ipv6_list: ipv6_list.append(ipv6)
            if netifaces.AF_LINK  in addrs: mac = addrs[netifaces.AF_LINK][0]['addr']
        except: pass
        if not ipv4 or ipv4.startswith('169.254'):
            try:
                stats = psutil.net_if_addrs()
                for iface, addrs_list in stats.items():
                    if iface.lower().replace(' ', '') == iface_name.lower().replace(' ', ''):
                        for addr in addrs_list:
                            if addr.family == psutil.AF_LINK and not mac: mac = addr.address
                            elif addr.family == 2:  ipv4 = addr.address
                            elif addr.family == 23:
                                ipv6 = addr.address.split('%')[0]
                                if ipv6 not in ipv6_list: ipv6_list.append(ipv6)
                        break
            except: pass
        return ipv4, ipv6_list, mac

    def detect_connection_type(self, iface_name):
        name_lower = iface_name.lower()
        for kw in ['wlan', 'wifi', 'wireless', 'wl']:
            if kw in name_lower: return "Wi-Fi"
        for kw in ['eth', 'enp', 'ens', 'enx', 'ethernet', 'realtek', 'intel']:
            if kw in name_lower: return "Ethernet"
        if platform.system() == "Linux":
            if os.path.exists(f"/sys/class/net/{iface_name}/wireless"): return "Wi-Fi"
            return "Ethernet"
        return "Ethernet"

    def update_connection_status(self):
        if not self.current_interface:
            self.lbl_conn.config(text="--")
            return
        ipv4, ipv6_list, mac = self.get_interface_addresses(self.current_interface)
        conn_type = self.detect_connection_type(self.current_interface)
        network   = self.get_network_name()

        ipv6_display = "no asignada"
        if ipv6_list:
            g6 = [x for x in ipv6_list if not x.startswith('fe80') and x != '::1']
            src = g6[0] if g6 else ipv6_list[0]
            ipv6_display = src[:36] + ("…" if len(src) > 36 else "")

        self.net_iface_var.set(self.current_interface[:30])
        self.net_type_var.set(conn_type)
        self.net_ipv4_var.set(ipv4 if ipv4 else "no asignada")
        self.net_ipv6_var.set(ipv6_display)
        self.net_mac_var.set(mac if mac else "--")
        self.net_ssid_var.set(network)

        self.lbl_conn.config(text="● ACTIVA", fg=COLORS["accent_green"])
        self.lbl_iface.config(text=self.current_interface[:30])
        self.lbl_type.config(text=conn_type)
        self.lbl_ipv4.config(text=ipv4 if ipv4 else "no asignada")
        self.lbl_ipv6.config(text=ipv6_display)
        self.lbl_mac.config(text=mac if mac else "--")
        self.lbl_net.config(text=network)
        self.iface_toolbar_label.config(text=f"INTERFAZ: {self.current_interface}")

    def start_network_monitor(self):
        def update():
            if not self.sniffing:
                new_iface = self.get_active_interface()
                if new_iface != self.current_interface:
                    self.current_interface = new_iface
                    self.update_connection_status()
            self.root.after(5000, update)
        self.root.after(5000, update)

    def _extract_pkt_info(self, pkt):
        mac_src = pkt[Ether].src if pkt.haslayer(Ether) else "ff:ff:ff:ff:ff:ff"
        mac_dst = pkt[Ether].dst if pkt.haslayer(Ether) else "ff:ff:ff:ff:ff:ff"
        
        if pkt.haslayer(ARP):
            ip_src, ip_dst = pkt[ARP].psrc, pkt[ARP].pdst
            proto = "ARP"
        elif pkt.haslayer(IP):   
            ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
            if pkt.haslayer(TCP):  proto = "TCP"
            elif pkt.haslayer(UDP):  proto = "UDP"
            elif pkt.haslayer(ICMP): proto = "ICMP"
            else: proto = f"IPv4 (0x{pkt[IP].proto:02x})"
        elif pkt.haslayer(IPv6): 
            ip_src, ip_dst = pkt[IPv6].src, pkt[IPv6].dst
            if pkt.haslayer(TCP):  proto = "TCP"
            elif pkt.haslayer(UDP):  proto = "UDP"
            elif pkt[IPv6].nh == 58: proto = "ICMPv6"
            else: proto = f"IPv6 (0x{pkt[IPv6].nh:02x})"
        else:                    
            ip_src, ip_dst = "---", "---"
            proto = "Otro"
            
        return mac_src, mac_dst, ip_src, ip_dst, proto

    def procesar_paquete(self, pkt):
        if self.sniffing:
            self.paquetes.append(pkt)
            idx = len(self.paquetes) - 1
            mac_src, mac_dst, ip_src, ip_dst, proto = self._extract_pkt_info(pkt)
            
            if "TCP" in proto: tag = "TCP"
            elif "UDP" in proto: tag = "UDP"
            elif "ICMP" in proto: tag = "ICMP"
            elif "ARP" in proto: tag = "ARP"
            else: tag = "Otro"
            
            row_tag = "even" if idx % 2 == 0 else "odd"

            def _insert():
                self.tree_lista.insert("", tk.END, values=(idx, proto, mac_src, mac_dst, ip_src, ip_dst), tags=(tag, row_tag))
                children = self.tree_lista.get_children()
                if children: self.tree_lista.see(children[-1])
                
                self.counter_total.increment()
                if   tag == "TCP":   self.counter_tcp.increment()
                elif tag == "UDP":   self.counter_udp.increment()
                elif tag == "ARP":   self.counter_arp.increment()
                elif tag == "ICMP":  self.counter_icmp.increment()
                else:                self.counter_other.increment()

            self.root.after(0, _insert)

    def sniff_thread(self):
        try:
            if self.current_interface: conf.iface = self.current_interface
            sniff(prn=self.procesar_paquete, stop_filter=lambda x: not self.sniffing, store=0)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error de captura", str(e)))
            self.root.after(0, self.stop_sniffing)

    def start_sniffing(self):
        if not self.current_interface:
            self.current_interface = self.get_active_interface()
            if not self.current_interface:
                messagebox.showwarning("Advertencia", "No se detectó interfaz de red.")
                return
        self.sniffing = True
        self.start_btn.config_state(tk.DISABLED)
        self.stop_btn.config_state(tk.NORMAL)
        self.status_badge.set_active(True)
        self.status_label_top.config(text="CAPTURANDO TODO", fg=COLORS["accent_green"])
        self.inspector_text.delete(1.0, tk.END)
        self._log(f"◈ MONITOREO PROMISCUO INICIADO\n", "header")
        self._log(f"  Modo:     ", "label")
        self._log(f"Interceptando Todo el Tráfico de Red (Sin Filtros)\n", "value")
        self._log(f"  Interfaz: ", "label")
        self._log(f"{self.current_interface}\n", "value")
        self._log(f"  Inicio:   ", "label")
        self._log(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n\n", "value")
        threading.Thread(target=self.sniff_thread, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config_state(tk.NORMAL)
        self.stop_btn.config_state(tk.DISABLED)
        self.status_badge.set_active(False)
        self.status_label_top.config(text="INACTIVO", fg=COLORS["text_dim"])
        self._log(f"\n◈ CAPTURA FINALIZADA  —  {time.strftime('%H:%M:%S')}\n", "header")

    def limpiar_tabla(self):
        self.paquetes = []
        for item in self.tree_lista.get_children(): self.tree_lista.delete(item)
        for item in self.tree_detalles.get_children(): self.tree_detalles.delete(item)
        self.inspector_text.delete(1.0, tk.END)
        for c in [self.counter_total, self.counter_tcp, self.counter_udp, self.counter_icmp, self.counter_arp, self.counter_other]:
            c.reset()
        self._log("◈ DATOS RESETEADOS\n", "header")

    def cargar_capas_paquete(self, event):
        sel = self.tree_lista.selection()
        if not sel: return
        for item in self.tree_detalles.get_children(): self.tree_detalles.delete(item)

        idx = int(self.tree_lista.item(sel[0], "values")[0])
        pkt = self.paquetes[idx]

        if pkt.haslayer(Ether):
            r = self.tree_detalles.insert("", tk.END, text="▸  CAPA 2  ·  Frame Ethernet (Direccionamiento Físico)", values=("",), open=True)
            self.tree_detalles.insert(r, tk.END, text="MAC Origen",      values=(pkt[Ether].src,))
            self.tree_detalles.insert(r, tk.END, text="MAC Destino",     values=(pkt[Ether].dst,))
            self.tree_detalles.insert(r, tk.END, text="Tipo Protocolo",  values=(hex(pkt[Ether].type),))

        if pkt.haslayer(ARP):
            r = self.tree_detalles.insert("", tk.END, text="▸  CAPA 2/3  ·  Protocolo ARP (Address Resolution Protocol)", values=("",), open=True)
            op_tipo = f"{pkt[ARP].op} (who-has / Request)" if pkt[ARP].op == 1 else f"{pkt[ARP].op} (is-at / Reply)"
            fields = [
                ("Tipo de Hardware (hwtype)",  hex(pkt[ARP].hwtype)),
                ("Tipo de Protocolo (ptype)",  hex(pkt[ARP].ptype)),
                ("Tamaño Hardware (hwlen)",    f"{pkt[ARP].hwlen} bytes"),
                ("Tamaño Protocolo (plen)",    f"{pkt[ARP].plen} bytes"),
                ("Operación (op)",             op_tipo),
                ("MAC Emisor ARP (hwsrc)",     pkt[ARP].hwsrc),
                ("IP Emisor ARP (psrc)",       pkt[ARP].psrc),
                ("MAC Destino ARP (hwdst)",    pkt[ARP].hwdst),
                ("IP Destino ARP (pdst)",      pkt[ARP].pdst),
            ]
            for name, val in fields: self.tree_detalles.insert(r, tk.END, text=name, values=(val,))

        if pkt.haslayer(IP):
            r = self.tree_detalles.insert("", tk.END, text="▸  CAPA 3  ·  Datagrama IPv4 (Direccionamiento Lógico)", values=("",), open=True)
            fields = [
                ("Versión",              pkt[IP].version),
                ("IHL (Header Length)",  f"{pkt[IP].ihl * 4} bytes"),
                ("Tipo de Servicio (ToS)", pkt[IP].tos),
                ("Longitud Total",       f"{pkt[IP].len} bytes"),
                ("Identificación ID",    pkt[IP].id),
                ("Flags IP",             str(pkt[IP].flags)),
                ("Fragment Offset",      pkt[IP].frag),
                ("TTL (Time To Live)",   pkt[IP].ttl),
                ("Protocolo Superior",   pkt[IP].proto),
                ("Checksum IP",          hex(pkt[IP].chksum)),
                ("IP Origen",            pkt[IP].src),
                ("IP Destino",           pkt[IP].dst),
            ]
            for name, val in fields: self.tree_detalles.insert(r, tk.END, text=name, values=(val,))

        elif pkt.haslayer(IPv6):
            r = self.tree_detalles.insert("", tk.END, text="▸  CAPA 3  ·  Datagrama IPv6 (Próxima Generación)", values=("",), open=True)
            fields = [
                ("Versión",                  pkt[IPv6].version),
                ("Clase de Tráfico (tc)",    pkt[IPv6].tc),
                ("Etiqueta de Flujo (fl)",   pkt[IPv6].fl),
                ("Longitud de Carga (plen)", f"{pkt[IPv6].plen} bytes"),
                ("Siguiente Encabezado (nh)",pkt[IPv6].nh),
                ("Límite de Saltos (hlim)",  pkt[IPv6].hlim),
                ("IP Origen v6",             pkt[IPv6].src),
                ("IP Destino v6",            pkt[IPv6].dst),
            ]
            for name, val in fields: self.tree_detalles.insert(r, tk.END, text=name, values=(val,))

        if pkt.haslayer(TCP):
            r = self.tree_detalles.insert("", tk.END, text="▸  CAPA 4  ·  Segmento TCP (Protocolo Control de Transmisión)", values=("",), open=True)
            fields = [
                ("Puerto Origen",             pkt[TCP].sport),
                ("Puerto Destino",            pkt[TCP].dport),
                ("Número de Secuencia",       pkt[TCP].seq),
                ("Acknowledgment (ACK Num)",  pkt[TCP].ack),
                ("Data Offset",               pkt[TCP].dataofs),
                ("Flags TCP",                 str(pkt[TCP].flags)),
                ("Ventana (Window Size)",     pkt[TCP].window),
                ("Checksum TCP",              hex(pkt[TCP].chksum)),
                ("Urg Pointer",               pkt[TCP].urgptr),
            ]
            for name, val in fields: self.tree_detalles.insert(r, tk.END, text=name, values=(val,))

        elif pkt.haslayer(UDP):
            r = self.tree_detalles.insert("", tk.END, text="▸  CAPA 4  ·  Datagrama UDP (Protocolo Datagramas de Usuario)", values=("",), open=True)
            fields = [
                ("Puerto Origen",  pkt[UDP].sport),
                ("Puerto Destino", pkt[UDP].dport),
                ("Longitud UDP",   f"{pkt[UDP].len} bytes"),
                ("Checksum UDP",   hex(pkt[UDP].chksum)),
            ]
            for name, val in fields: self.tree_detalles.insert(r, tk.END, text=name, values=(val,))

    def inspeccionar_campo(self, event):
        sel = self.tree_detalles.selection()
        if not sel: return
        item = sel[0]
        nombre = self.tree_detalles.item(item, "text")
        valores = self.tree_detalles.item(item, "values")
        valor   = valores[0] if valores else ""

        self.inspector_text.delete(1.0, tk.END)

        if nombre in self.diccionario_campos:
            self._log(f"◈ {nombre.upper()}\n", "header")
            if valor:
                self._log("  Valor en paquete: ", "label")
                self._log(f"{valor}\n\n", "value")
            self._log("  Descripción técnica:\n", "label")
            self._log(f"  {self.diccionario_campos[nombre]}\n", "body")
        else:
            self._log(f"◈ {nombre}\n", "header")
            self._log("\n  Selecciona un campo específico\n  para ver su explicación técnica.\n", "dim")

    def inicializar_diccionario(self):
        return {
            "MAC Origen": "Dirección física de la tarjeta de red emisora (Capa 2 Ethernet).",
            "MAC Destino": "Dirección física de destino en el mismo segmento de red local.",
            "Tipo Protocolo": "Indica el protocolo encapsulado en la capa superior (0x0800=IPv4, 0x0806=ARP).",
            "Versión": "Indica la versión del protocolo IP utilizada (4 o 6).",
            "IHL (Header Length)": "Longitud del encabezado IP expresado en palabras de 32 bits.",
            "Tipo de Servicio (ToS)": "Mecanismo para definir prioridades y calidad de servicio (QoS).",
            "Longitud Total": "Tamaño absoluto del paquete IP en bytes (encabezado + datos).",
            "Identificación ID": "Campo utilizado para rastrear fragmentos divididos de un datagrama.",
            "Flags IP": "Indicadores que controlan si un paquete puede o no ser fragmentado.",
            "TTL (Time To Live)": "Tiempo de vida del paquete. Se reduce en 1 en cada router para evitar bucles infinitos.",
            "Protocolo Superior": "Identifica el protocolo de transporte de Capa 4 (6=TCP, 17=UDP, 1=ICMP).",
            "Checksum IP": "Valor de redundancia cíclica para comprobar que el encabezado no sufra alteraciones.",
            "IP Origen": "Dirección lógica IPv4 asignada a la máquina emisora.",
            "IP Destino": "Dirección lógica IPv4 de destino final de la transmisión.",
            "Puerto Origen": "Puerto de salida asignado dinámicamente por la aplicación que originó la sesión.",
            "Puerto Destino": "Puerto de escucha asignado al servicio que recibirá la información.",
            "Número de Secuencia": "Sincroniza el orden correcto de los bytes de datos transmitidos por TCP.",
            "Acknowledgment (ACK Num)": "Indica al emisor cuál es el número del siguiente byte que se espera recibir.",
            "Flags TCP": "Bits de control que delimitan el tipo de mensaje de control (SYN, ACK, FIN, RST, PSH).",
            "Ventana (Window Size)": "Mapea la cantidad de almacenamiento disponible en buffer que tiene el receptor.",
            "Checksum TCP": "Garantiza la integridad libre de errores tanto del encabezado como de los datos TCP.",
            "Longitud UDP": "Indica el tamaño del datagrama UDP en bytes incluyendo su propia cabecera.",
            "Checksum UDP": "Verificación matemática opcional pero recomendada de la integridad del paquete UDP.",
            "IP Origen v6": "Dirección IP lógica de 128 bits correspondiente al nodo origen.",
            "IP Destino v6": "Dirección IP lógica de 128 bits correspondiente al nodo receptor.",
            "Clase de Tráfico (tc)": "Determina prioridades de envío en redes saturadas bajo IPv6.",
            "Etiqueta de Flujo (fl)": "Mantiene el ruteo idéntico para paquetes pertenecientes al mismo flujo continuo.",
            "Longitud de Carga (plen)": "Mide el tamaño de los datos encapsulados después del encabezado de 40 bytes de IPv6.",
            "Siguiente Encabezado (nh)": "Determina el tipo de cabecera de extensión o protocolo de transporte que prosigue.",
            "Límite de Saltos (hlim)": "Equivalente exacto del TTL de IPv4; cada router descuenta 1.",
            "Data Offset": "Especifica dónde terminan las cabeceras TCP y dónde comienzan los datos crudos.",
            "Urg Pointer": "Señala la ubicación exacta donde terminan datos considerados urgentes.",
            "Fragment Offset": "Determina el orden exacto en que debe acoplarse un fragmento dentro del paquete original.",
            "Tipo de Hardware (hwtype)": "Mapea la infraestructura física sobre la que opera (0x1 indica redes Ethernet estándar).",
            "Tipo de Protocolo (ptype)": "El protocolo de red al cual ARP traduce las peticiones físicas (0x0800 para IPv4).",
            "Tamaño Hardware (hwlen)": "Tamaño de las direcciones físicas expresado en bytes; en redes de área local es 6.",
            "Tamaño Protocolo (plen)": "Tamaño de las direcciones lógicas IP; en direccionamiento IPv4 el valor es 4.",
            "Operación (op)": "Determina el rol del paquete ARP: Código 1 para solicitudes (Request), Código 2 para respuestas (Reply).",
            "MAC Emisor ARP (hwsrc)": "Dirección de hardware de la máquina que publica el mensaje ARP en la red local.",
            "IP Emisor ARP (psrc)": "Dirección IP lógica asociada al emisor que publica el mensaje ARP.",
            "MAC Destino ARP (hwdst)": "Dirección física destino. En un Request, viaja en ceros porque se desconoce.",
            "IP Destino ARP (pdst)": "Dirección IP destino de la cual se está intentando averiguar su MAC física correspondiente."
        }


if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
