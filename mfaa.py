#Reporting Tool: Multiple FortiSIEM Alert Analysis | Version:2.0  | Created By: StaryDarkz  | Telegram: https://t.me/StaryDarkz 

import docx, operator, time, datetime, re, httplib2
import matplotlib.pyplot as plt
import numpy as np
from docx.enum.text import WD_ALIGN_PARAGRAPH 
from xml.dom.minidom import Node, parseString, parse
from Resources.config import allsiem
import xml.etree.ElementTree as ET
from reportlab.platypus import SimpleDocTemplate

#Funciones DOCX
def add_table(plantilla, data): 

    table = plantilla.add_table(rows = 0, cols=2, style = "Grid Table 4 - Accent 11")          
    row = table.add_row().cells 

    row[0].text = "Rule Name"
    row[1].text = "Total Alertas"

    for incidente in data.keys():
        row = table.add_row().cells
        row[0].text = incidente
        row[1].text = str(data[incidente])

def graficar_gbarras(keys, values, gname):
    """ Grafico de barras"""

    #Graficar solo el TOP 10
    if len(keys) > 10:
        keys = keys[0:10]
        values = values[0:10]


    plt.rcParams.update(plt.rcParamsDefault) #Reinicia Estilo
    fig, ax = plt.subplots(figsize=(7, 4)) #Aplica Tamaño Figura
    ax.barh(keys, values, height=0.8) #Agrega Datos Ejes
    ax.invert_yaxis() #Invierte Impresión de Valores
    ax.xaxis.grid(False); ax.yaxis.grid(False) #Elimina Ejes Fondo Figura

        #Genera Etiquetas (Valores) Lado Derecha Barras
    for i in range(len(values)):
        ax.text(values[i]+1, i, values[::][i], color='black', fontsize=8, ha='center',  fontweight='bold', bbox=dict(facecolor='skyblue', alpha=0.3))

    plt.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=False) #Elimina Datos Eje X
    plt.yticks(fontsize=8) #Etiquetas Eje Y
    fig.tight_layout()

    #Save Image
    name = f"{gname}.png"
    plt.savefig(name)
    plt.close()

def graficar_gbarras_CLIENTES(data_json, gname):
    """ Grafico de barras"""
    keys = []
    values = []

    for element in data_json:
        keys.append(element)
        values.append(data_json[element])

    #Graficar solo el TOP 10
    if len(keys) > 10:
        keys = keys[0:10]
        values = values[0:10]


    plt.rcParams.update(plt.rcParamsDefault) #Reinicia Estilo
    #plt.style.use('seaborn') #Aplica Estilo
    fig, ax = plt.subplots(figsize=(7, 4)) #Aplica Tamaño Figura
    ax.barh(keys, values, height=0.8) #Agrega Datos Ejes
    ax.invert_yaxis() #Invierte Impresión de Valores
    ax.xaxis.grid(False); ax.yaxis.grid(False) #Elimina Ejes Fondo Figura

        #Genera Etiquetas (Valores) Lado Derecha Barras
    for i in range(len(values)):
        ax.text(values[i]+1, i, values[::][i], color='black', fontsize=8, ha='center',  fontweight='bold', bbox=dict(facecolor='skyblue', alpha=0.3))

    plt.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=False) #Elimina Datos Eje X
    plt.yticks(fontsize=8) #Etiquetas Eje Y
    fig.tight_layout()

    #Save Image
    name = f"{gname}.png"
    plt.savefig(name)
    plt.close()


#Funciones de la API FortiSIEM
def select_query(xmlquery, input_time_user, email_alert):
    
    timestamp = int(time.time())

    custom_time = 86400 * input_time_user

    time_start = timestamp - custom_time
    time_end = timestamp
    xml_incident_count = f"""<?xml version="1.0" encoding="UTF-8"?>
    <Reports>
    <Report baseline="" rsSync="">
        <Name>Incident Notification Count</Name>
        <Description> Total de Notificaciones con email alert especificado</Description>
        <CustomerScope groupByEachCustomer="false">
        </CustomerScope>
        <SelectClause>
            <AttrList>ruleName,COUNT(DISTINCT incidentId)</AttrList>
        </SelectClause>
        <OrderByClause>
            <AttrList>COUNT(DISTINCT incidentId) DESC</AttrList>
        </OrderByClause>
        <PatternClause window="3600">
            <SubPattern id="1164394" name="Filter_OVERALL_STATUS">
                <SingleEvtConstr>(phEventCategory = 3  AND  eventType = "PH_INCIDENT_ACTION_STATUS" AND actionName CONTAIN "{email_alert}")</SingleEvtConstr>
                <GroupByAttr>ruleName</GroupByAttr>
            </SubPattern>
        </PatternClause>
        <userRoles>
            <roles custId="2001">1169250</roles>
        </userRoles>
        <SyncOrgs/><ReportInterval>
            <Low>{time_start}</Low>
            <High>{time_end}</High>error
        </ReportInterval>
        <TrendInterval>auto</TrendInterval>
        <TimeZone/>
    </Report>
    </Reports>"""
 
    if "xml_incident_count" == xmlquery:
        return xml_incident_count

def get_queryfromsiem(ip_siem, user, password, xml_query):

    url = "https://" + ip_siem + ":443/phoenix/rest/query/"
    urlfirst = url + "eventQuery"
    
    h = httplib2.Http(disable_ssl_certificate_validation=True)
    h.add_credentials(user, password)
    
    header = {'Content-Type': 'text/xml'}
    
    doc = parseString(xml_query)
    t = doc.toxml()

    if '<DataRequest' in t:
        t1 = t.replace("<DataRequest", "<Reports><Report")
    else:
        t1 = t
    if '</DataRequest>' in t1:
        t2 = t1.replace("</DataRequest>", "</Report></Reports>")
    else:
        t2 = t1

    resp, content = h.request(urlfirst, "POST", t2, header)
    
    #print (resp, content)
    
    queryId = content.decode("utf-8")
    if "xml version" in queryId:
        queryId = extrat_data_query(queryId)
        
    if 'error code="255"' in queryId:
        print ("Query Error, check sending XML file.")
        #exit()
        return "Error"

    urlSecond = url + "progress/" + queryId
    if resp['status'] == '200':
        resp, content = h.request(urlSecond)

    else:
        print ("appServer doesn't return query. Error code is %s" % resp['status'] )
        #exit()
        return "Error"


    while True:
        resp, content = h.request(urlSecond)
        try: 
            progreso = extrat_data_status(content)
            #print (progreso)
            if progreso == 100:
                break
        except:
            while content.decode("utf-8") != '100':
                resp, content = h.request(urlSecond)
            break

    outXML = []
   
    
    urlFinal = url + 'events/' + queryId + '/0/1000'
    resp, content = h.request(urlFinal)
    
    #print (resp, "\n\n", content)

    if content != '':
        outXML.append(content.decode("utf-8"))

    p = re.compile('totalCount="\d+"')
    mlist = p.findall(content.decode())
    
    
    if mlist[0] != '':
        mm = mlist[0].replace('"', '')
        m = mm.split("=")[-1]
        num = 0
        if int(m) > 1000:
            num = int(m) / 1000
            if int(m) % 1000 > 0:
                num += 1
        if num > 0:
            for i in range(num):
                urlFinal = url + 'events/' + queryId + '/' + str((i + 1) * 1000) + '/1000'
                resp, content = h.request(urlFinal)
                if content != '':
                    outXML.append(content.decode("utf-8"))
    else:
        print ("no info in this report.")
        return "Error"
    data = dumpXML(outXML)
    return data

def extrat_data_status(xml_string):
    query = ET.fromstring(xml_string).find('./result/progress').text
    return int(query)

def extrat_data_query(xml):
    query = (ET.fromstring(xml).get('requestId'))
    timestamp = ET.fromstring(xml).find('./result/expireTime').text
    resultado = f"{query},{timestamp}"
    return resultado

def dumpXML(xmlList):
    param = []
    for xml in xmlList:
        doc = parseString(xml.encode('ascii', 'xmlcharrefreplace'))
    for node in doc.getElementsByTagName("events"):
        for node1 in node.getElementsByTagName("event"):
            mapping = {}
            for node2 in node1.getElementsByTagName("attributes"):
                for node3 in node2.getElementsByTagName("attribute"):
                    itemName = node3.getAttribute("name")
                    for node4 in node3.childNodes:
                        if node4.nodeType == Node.TEXT_NODE:
                            message = node4.data
                            if '\n' in message:
                                message = message.replace('\n', '')
                            mapping[itemName] = message
            param.append(mapping)
    return param


#Funciones de analisis
def generate_eventcount(param, element):
    if len(param) == 0:
        print (f"No records found on {element}")
        return "Error"

    else:
        keys = param[0].keys()
        dicdata = {}

        for item in param:
            try:
                dicdata[item["ruleName"]] = int(item["COUNT(DISTINCT incidentId)"])
            except:
                dicdata[item["ruleName"]] = int(item["COUNT(*)"])
        return dicdata

def extrat_keyandvalue_CLIENTS(data):

    datanew = {}

    for cliente in data:
        totalalerts = 0
        for rulenamevalue in data[cliente]:
            totalalerts += data[cliente][rulenamevalue]
        
        datanew[cliente] = totalalerts
    return datanew

def get_time_for_reportname():

    fecha = datetime.datetime.now()
    fecha = fecha.strftime("%Y_%m_%d %H_%M") 

    return fecha

def extrat_keyandvalue(data):
    dataend = {}

    for element in data:
        dataend[element] = data[element]
    return dataend
   

#Funciones Generales
def menu(select):
    import getpass

    if select == "login":
        print ("\nIngresa tus credenciales:\n")
        username = input("Username:\n-->")
        password = getpass.getpass("Password:\n-->")
        return username, password

    elif select == "select_time":
        print ("Especifica el rango de tiempo del reporte:\n\n")
        time = int(input("Cantidad de Dias hacia atras\n-->"))
        return time

    elif select == "email_alert":
        print ("Especifica el correo de notificaciones:")
        email = input("Email: -->")
        return email
 
def main(allsiem = allsiem):
    """ Ejecucion inicial """

    #Datos de entrada requeridos
    username, password = menu("login")
    time = menu("select_time")
    email_alert = menu("email_alert")

    #Cargar la plantilla
    plantilla = docx.Document("resources/plantillaMFAA.docx")
    plantilla.add_page_break()

    #Iteracion de cada cliente
    alldata = {}
    alldatabysiem = {}
    totalalerts = 0

    for element in allsiem:
        """ Iteracion por cada cliente"""
        

        data = get_queryfromsiem(allsiem[element], f"super/{username}", password, select_query("xml_incident_count", time, email_alert))
        if data == "Error":
            print (element, "is not ok")
            continue
        topincidentsdata = generate_eventcount(data, element)
        if topincidentsdata == "Error":
            print (element, "is not ok")
            continue
        alldatabysiem[element]  = generate_eventcount(data, element)
        
        print (element,'is ok')

        #Unir toda la data a topincidentsdata
        for element in topincidentsdata:
            if element not in list(alldata):
                alldata[element] = topincidentsdata[element]
            elif element in list(alldata):
                alldata[element] += topincidentsdata[element]
            
            totalalerts += topincidentsdata[element]
        
    
    # TOP Grafico FortiSIEM Count Alerts
    format = plantilla.add_heading(f"All FortiSIEM Alerts ({totalalerts} Alerts)", 1)

    format = plantilla.add_heading("TOP Multiple FortiSIEM Count Alert", 2)
    format.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    data_extrated = extrat_keyandvalue_CLIENTS(alldatabysiem)
    data_sorted = dict(sorted(data_extrated.items(), key=lambda x: x[1], reverse=True))
    
    graficar_gbarras_CLIENTES(data_sorted, "topsiem")
    plantilla.add_picture("topsiem.png", width=docx.shared.Cm(19), height=docx.shared.Cm(10))

    #Detalles del count de alertas notificadas
    plantilla.add_heading("Details Multiple Fortisiem Count Alerts", 2)
    add_table(plantilla, data_sorted)
    plantilla.add_page_break()


    # Top Grafico Alertas notificadas
    format = plantilla.add_heading("TOP Notification Alerts", 2)
    format.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER

    
    
    data_extrated2 = extrat_keyandvalue(alldata)
    data_sorted2 = dict(sorted(data_extrated2.items(), key=lambda x: x[1], reverse=True))

    
    graficar_gbarras_CLIENTES(data_sorted2 , "topincidents")
    plantilla.add_picture("topincidents.png", width=docx.shared.Cm(19), height=docx.shared.Cm(10))
    plantilla.add_page_break()
   
    plantilla.add_heading(f"Details Notification Alerts", 2)
    add_table(plantilla, data_sorted2)
    plantilla.add_page_break()


    #Generar reporte
    fecha = get_time_for_reportname()
    output_docx = (f"output/MFAA_{fecha}.docx")
    
    plantilla.save(output_docx)

    print ("\n\nTotal Alertas:", totalalerts)
    print (data_sorted)

main()