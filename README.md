# Multi-FortiSIEM Alert Analyzer

Esta herramienta de generación de informes automatizados, desarrollada con el lenguaje de programación Python aprovecha la API de FortiSIEM para producir informes en formato DOCX que incluyen gráficos y tablas detalladas sobre las alertas e incidentes de seguridad reportados por uno o varios servidores FortiSIEM hacia una única dirección de correo electrónico.

Ofrece un análisis exhaustivo de la cantidad de alertas recibidas en una dirección de correo determinada, especialmente útil en entornos donde varios servidores FortiSIEM envían alertas a una misma dirección de correo electrónico. Esta funcionalidad es ideal para SOC MSSP que gestionan múltiples clientes, cada uno con su propio servidor FortiSIEM.

Con esta herramienta, obtendrás un ranking de las alertas más frecuentes, una tabla detallada de todos los casos de uso reportados, así como un análisis de los servidores FortiSIEM que generan la mayor cantidad de alertas. Este proyecto tiene como objetivo proporcionar una amplia gama de funciones analíticas adicionales para una mejor comprensión y gestión de la seguridad.

## Requisitos
- Sistema Operativo: Windows/Linux
- Python3
- Version de FortiSIEM: v5.X en adelante
- Ultima version testeada: v7.1 

Librerias:
```bash
pip3 install httplib2 matplotlib xml docx
```
## Descarga y Configuracion

1. Descargar repositorio:

```bash
git clone https://github.com/starydarkz/Multiple_FortiSIEM_Alert_Analys.git
```
2. Instale las librerias necesarias:
```bash
pip3 install httplib2 matplotlib xml docx
```
3. Configurar lista de Servidores FortiSIEM
```
1. Editar archivo de configuracion config.py
3. Agregar la lista de SIEMS y eliminar la lista de ejemplo, como se muestra a continuacion:
allsiem = {
    "NOMBRE DEL SIEM":"DIRECCION IP DEL SIEM", 
    "SIEM2":"127.0.0.2", 
    "SIEM3":"127.0.0.3"
    }
```

3. Ejecute la herramienta y rellene los datos solicitados:
```bash
python3 mfaa.py
```
- Username: --> Nombre de usuario que usa para ingresar el FortiSIEM
- Password: --> Contraseña que usa para ingresar el FortiSIEM (Esta oculto)
- Cantidad de Dias hacia atras --> Numero de dias en relativo para extraer la data del FortISIEM
- Especifica el correo de notificaciones --> Correo electronico usado para enviar las alertas desde el FortiSIEM (esto lo puede encontrar en la politica de notificaciones de incidentes del FortiSIEM)
