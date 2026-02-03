# 👾 ShodanLookup 👾

**Una herramienta de línea de comandos para consultar la API de Shodan y explorar información de hosts de forma rápida y visual.**

</div>

``` bash
▄█████ ▄▄ ▄▄  ▄▄▄  ▄▄▄▄   ▄▄▄  ▄▄  ▄▄ 
▀▀▀▄▄▄ ██▄██ ██▀██ ██▀██ ██▀██ ███▄██ 
█████▀ ██ ██ ▀███▀ ████▀ ██▀██ ██ ▀██ 
                                        By CrIsTiiAnPvP
██      ▄▄▄   ▄▄▄  ▄▄ ▄▄ ██  ██ ▄▄▄▄  
██     ██▀██ ██▀██ ██▄█▀ ██  ██ ██▄█▀ 
██████ ▀███▀ ▀███▀ ██ ██ ▀████▀ ██                           
```

---

## 📖 Descripción

**ShodanLookup** es un script de Python que facilita la obtención de información detallada sobre direcciones IP utilizando la potente API de [Shodan](https://www.shodan.io/). La herramienta presenta los datos de una manera clara y organizada, utilizando colores para resaltar la información más relevante, como vulnerabilidades y servicios.

## ✨ Características Principales

- **Configuración Automática**: Detecta si tienes una clave de API de Shodan. Si no, te pedirá una y la guardará en un archivo `.env` para futuros usos.
- **Consulta de IP**: Obtén información completa de un host, incluyendo:
  - Geolocalización (país, ciudad) con bandera emoji.
  - Organización, ISP y sistema operativo.
  - Nombres de host y dominios asociados.
  - Puertos abiertos y servicios en ejecución.
- **Visualización de Vulnerabilidades**: Identifica y lista las vulnerabilidades (CVEs) asociadas a los servicios, mostrando su puntuación CVSS y un resumen del problema.
- **Interfaz Colorida**: Utiliza `colorama` y un módulo `rainbow` para una experiencia de usuario más amigable y una fácil identificación de datos críticos.
- **Menú Interactivo**: Navega por las diferentes funciones de la herramienta de forma sencilla.

## 📋 Requisitos

- Python 3.x
- Una clave de API de Shodan. Puedes obtenerla en [https://account.shodan.io/](https://account.shodan.io/).

## ⚙️ Instalación

1. Clona este repositorio o descarga los archivos:

    ```bash
    git clone https://github.com/CrIsTiiAnPvP/ShodanLookup.git
    cd ShodanLookup
    ```

2. Crea un entorno virtual (recomendado):

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # En Windows: .venv\Scripts\activate
    ```

3. Instala las dependencias:

    Y luego instalarlo con:

    ```bash
    pip install colorama shodan
    ```

## 🚀 Uso

1. Ejecuta el script:

    ```bash
    python main.py
    ```

2. La primera vez que lo ejecutes, te pedirá tu clave de API de Shodan. Introdúcela y la herramienta la guardará en un archivo `.env` para no volver a pedirla.

3. Selecciona una opción del menú:
    - **`[1] Search by IP address`**: Introduce la IP que deseas investigar.

### Ejemplo de Salida

```bash

[+] Results for IP: 8.8.8.8

[*] IP Address: 8.8.8.8 | Mountain View (🇺🇸 United States/CA)
[*] Organization: Google LLC
[*] ISP: Google LLC
[*] Hostnames: dns.google | Domains: dns.google
[*] Operating System: None
[*] Last Update: 03-02-2026 07:00:01

[========================================]
[*] Port: 53/tcp | Product: N/A
[*] Port: 53/udp | Product: N/A
[*] Port: 443/tcp | Product: N/A
[========================================]

```

## ⚖️ Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
