import sys
import os
from functions import functions
from prettytable import PrettyTable
from tqdm import tqdm

if __name__ == "__main__":
    os.system("cls")
    numero_argumentos = len(sys.argv)    
    if numero_argumentos == 2:
        url = 'https://api.abuseipdb.com/api/v2/check'
        API_key = 'a415ba70cfbb747a1c517552d41462540e6a0a35ac4ea462b6b2aa4588d0d4e41a9714f9e876f1db'

        functions = functions(url, API_key)
        functions.main_banner()    
        captura_trafico = sys.argv[1]
        lista_paquetes = functions.lista_paquetes(captura_trafico)
        #numero_paquetes = functions.numero_paquetes(lista_paquetes)
        ips_destino = functions.lista_ips_destino(lista_paquetes)        
        print(">> Numero de paquetes [ " +str(numero_paquetes)+ " ]\n" )
        tabla = PrettyTable(['Direcciones IP', 'Puntaje', 'pais', 'Numero de Reportes'])     
        for ip in tqdm(ips_destino):
            check_ip = functions.check_ip_publica_o_privada(ip)
            if check_ip != 'PRIVATE':                
                report = functions.check_IP_abuseipdb(ip)
                tabla.add_row([report[0],report[1],report[2],report[3]])
        print(tabla)
    else:
        functions.help()