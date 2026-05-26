## Requisitos Previos (Ubuntu / Linux)

Antes de ejecutar el sniffer, asegúrate de cumplir con los siguientes requisitos:

- Sistema operativo Linux (U otras distros basadas en Debian)
- Python 3 instalado
- Permisos de superusuario (sudo)
- Librerías necesarias instaladas:
  - scapy
  - tkinter

## Instalación de dependencias

Instalar Scapy:

```bash
pip install scapy
```
Instalar Tkinter en Ubuntu/Debian:
```bash
sudo apt install python3-tk
```
## Ejecución del Sniffer

El ejecutable Linux fue generado usando PyInstaller en modo --onedir.

La estructura esperada es:
```bash
home
|
tu-usuario
|
Descargas (o la carpeta dónde lo guardaste al descargar)
|
Sniffer_Final_Linux/
├── Sniffer_Final_Linux
└── _internal/
```
**IMPORTANTE:
No debes intentar ejecutar la carpeta directamente.**

## Pasos correctos
1- Abrir terminal
2- Entrar al directorio del ejecutable:
```bash 
cd /ruta/del/proyecto/Sniffer_Final_Linux
```
Ejemplo: 
```bash
cd /home/usuario/Descargas/dist/Sniffer_Final_Linux
```
3- Dar permisos de ejecución: 
```bash
chmod +x Sniffer_Final_Linux
```
4- Ejecutar como super usuario: 
```bash
sudo ./Sniffer_Final_Linux
```

## Error común

Si aparece:
```bash
-bash: ./Sniffer_Final_Linux: Es un directorio
```
significa que se intentó ejecutar la carpeta en lugar del archivo ejecutable interno.

Debes entrar primero a la carpeta y luego ejecutar el binario.
