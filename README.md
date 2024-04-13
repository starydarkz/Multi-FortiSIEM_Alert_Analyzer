# Reporting Tool: Multiple FortiSIEM Alert Analys

Esta herramienta de reportes automatizados es capaz de generar un reporte en formato DOCX con graficos y tablas sobre las alertas incidentes de seguridad alertadas reportadas por uno o mas FortiSIEMs hacia un correo en concreto.

Obtenga un analisis sobre la cantidad de alertas recibidas hacia una direccion de correo en un ambiente en donde varios servidores de FortiSIEM envian a una misma direccion de correo electronico, ideal para SOC MSSP en donde administran diferentes clientes y cada uno en un servidor a parte.

Con esta herramienta obtendra un TOP de las alertas que mas se generan, una tabla con todos los casos de uso reportadas, un TOP de cuales servidores de FortiSIEM son los que mas generan alertas y mas funciones de analisis.


## Requisitos
- Sistema Operativo: Windows/Linux
- Python3

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
Username: --> Nombre de usuario que usa para ingresar el FortiSIEM
Password: --> Contraseña que usa para ingresar el FortiSIEM (Esta oculto)
Cantidad de Dias hacia atras --> Numero de dias en relativo para extraer la data del FortISIEM
Especifica el correo de notificaciones --> Correo electronico usado para enviar las alertas desde el FortiSIEM (esto lo puede encontrar en la politica de notificaciones de incidentes del FortiSIEM)