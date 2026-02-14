# Go-Sniffer: Analizador de Tráfico de Red en Golang

**Go-Sniffer** es una herramienta potente de análisis de red pasiva desarrollada en Go, diseñada para capturar e inspeccionar paquetes de red en tiempo real.

## 🦈 Características

*   **Captura de paquetes en tiempo real:** Monitoriza el tráfico de red de forma instantánea en cualquier interfaz disponible.
*   **Decodificación de capas:** Análisis detallado de capas IPv4, TCP y UDP.
*   **Filtrado avanzado BPF:** Utiliza filtros Berkeley Packet Filter (BPF) para capturar solo lo que te interesa (ej: `tcp port 80`).
*   **Inspección de payload HTTP:** Identificación de tráfico HTTP y detección de credenciales o datos sensibles en texto claro (como usuarios y contraseñas).

## 📋 Requisitos

Para compilar y ejecutar esta herramienta, necesitas:

*   **Go** (versión 1.24 o superior recomendada).
*   **Bibliotecas de captura de paquetes:**
    *   **Linux:** `libpcap-dev` (ej: `sudo apt-get install libpcap-dev`)
    *   **macOS:** `libpcap` (instalado por defecto).
    *   **Windows:** [Npcap](https://nmap.org/npcap/) (asegúrate de instalarlo con el modo de compatibilidad de API de WinPcap).
*   **Privilegios de administrador:** Se requiere `sudo` o permisos de root para capturar paquetes en las interfaces de red.

## 🚀 Instalación y Uso

### Compilación

Clona el repositorio y compila el binario:

```bash
go build -o go-sniffer main.go
```

### Uso

Primero, puedes listar las interfaces disponibles:

```bash
sudo ./go-sniffer -list
```

Para iniciar la captura en una interfaz específica (ej: `eth0`) con un filtro BPF opcional:

```bash
sudo ./go-sniffer -device eth0 -filter "tcp port 80"
```

Para guardar los paquetes capturados en un archivo `.pcap`:

```bash
sudo ./go-sniffer -device eth0 -output captura.pcap
```

Los archivos generados son compatibles con **Wireshark** y **tcpdump** para análisis posterior.

Si deseas capturar todo el tráfico IPv4 en `eth0`:

```bash
sudo ./go-sniffer -device eth0
```

## ⚠️ DISCLAIMER (Aviso Legal)

Esta herramienta ha sido creada únicamente con **fines educativos y de prueba de penetración ética** en entornos controlados o redes de las cuales seas el propietario.

El uso de esta herramienta para interceptar tráfico de red sin el permiso explícito de los propietarios de los sistemas es **ilegal** en muchas jurisdicciones. El autor no se hace responsable del mal uso de este software ni de cualquier daño o consecuencia legal derivada del mismo. Úsalo con responsabilidad.
