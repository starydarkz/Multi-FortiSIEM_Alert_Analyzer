<img src="Resources/logo.png" alt="Avatar del Bot"/>

Esta herramienta de generación de informes automatizados, desarrollada con el lenguaje de programación Python aprovecha la API de FortiSIEM para producir informes en formato DOCX que incluyen gráficos y tablas detalladas sobre las alertas e incidentes de seguridad reportados por uno o varios servidores FortiSIEM hacia una única dirección de correo electrónico.

Ofrece un análisis exhaustivo de la cantidad de alertas recibidas en una dirección de correo determinada, especialmente útil en entornos donde varios servidores FortiSIEM envían alertas a una misma dirección de correo electrónico. Esta funcionalidad es ideal para SOC MSSP que gestionan múltiples clientes, cada uno con su propio servidor FortiSIEM.

Esta herramienta genera unu archivo .docx con las siguientes caracteristicas:
- Grafico TOP 10 General de cantidad de alertas por instancias de SIEM  
- Grafico TOP 10 General de cantidad de alertas por nombre de reglas
- Grafico TOP 10 por instancia de SIEM de cantidad de alertas por nombre de regla
- Grafico de cantidad de alertas por hora (24 horas)
- Tablas de cantidad de alertas y reglas general y por instancia de SIEM
- Detalles del patron de recurrencia por cliente de las alertas

Este proyecto tiene como objetivo proporcionar una amplia gama de funciones analíticas adicionales para una mejor comprensión y gestión de la seguridad.

## Requisitos
- Python3
- Version de FortiSIEM: v5.x --> v7.1 


## Descarga y Configuracion

1. Descargar repositorio:

```bash
git clone https://github.com/starydarkz/Multiple_FortiSIEM_Alert_Analys.git
```
2. Instale las librerias necesarias:
```bash
pip3 install -r requeriments.txt
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
- Especifica el correo de notificaciones --> Correo electronico usado que se envian las alertas desde el FortiSIEM
