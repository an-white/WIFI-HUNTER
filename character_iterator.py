from tqdm import tqdm

from universal_connection import *


# incrementador de cadenas
def increment(pws, string_list):
    i = 0
    for i in range(len(pws) - 1, -1, -1):
        if pws[i] != string_list[-1]:
            for n in range(len(pws) - 1, i, -1):
                pws[n] = string_list[0]
            pws[i] = string_list[string_list.index(pws[i]) + 1]
            inc = True
            return pws, inc
    # last value possible
    if i == "0":
        inc = False
        return pws, inc


def numeric(networks, last, number_len):
    keys_found = 0
    for i in tqdm(range(last)):
        pw = "0" * (number_len - (len(str(i)))) + str(i)
        # test on networks
        for k in range(len(networks.Redes)):
            signal = create_new_connection(pw, networks.Redes[k])
            if signal:
                networks.drop(k, inplace=True)
                networks.reset_index(drop=True, inplace=True)
                print("\nSe ha conseguido una key c:\n")
                keys_found = +1

    return keys_found


def alfa_num(networks, string_len, n_tries):
    import string

    # test with alfa-numeric AN or special Characters
    t = "alfa-numeric"
    characters = list(string.digits + string.ascii_letters)

    if n_tries == 1:
        t = "Special Characters"
        characters = list(string.digits + string.ascii_letters + string.punctuation)

    pws = []

    # dimensiona la cadena a generar
    for i in range(string_len):
        pws.append("0")

    inc = True
    #
    # while inc and len(networks.Redes) > 0:
    #     keys = 0
    #     for i in range(len(characters)):
    #         pws[-1] = characters[i]
    #         pw = "".join(pws)
    #         ## Enviar a la funcion de test ##
    #         for k in range(len(networks.Redes)):
    #             ## conseguir como evaluar las cadenas inferiores a otras para descartar repetidos ##
    #             if networks.last[i] == pw:
    #                 networks.last[i]
    #             signal = key_test(pw, networks.Redes[k])
    #             if signal:
    #                 networks.drop(k, inplace=True)
    #                 networks.reset_index(drop=True, inplace=True)
    #                 keys = +1
    #     pws, inc = increment(pws, characters)

    return f"test with: {t} with length of: {str(string_len)}", keys


while True:
    try:
        dim = int(input("digits to try"))
        # password length
        test_type = input("tipo de cadena (num=0/alfaNum=1/alfaEspecial=2)")
        # list networks
        networks_listed = display_available_networks()
        last_num = int("1" + "0" * dim)

        # numeric
        if test_type == 0:
            keys = numeric(networks_listed, last_num, dim)
            break
        # alfa-numeric
        elif test_type == 1:
            log, keys = alfa_num(networks_listed, dim, 0)
            break
        # alfa-numeric with special characters
        elif test_type == "alfaEspecial":
            log, keys = alfa_num(networks_listed, dim, 1)
            break
        else:
            print("no valid value")
    except ValueError:
        print("setting default value = 8")
