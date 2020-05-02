from scapy.all import rdpcap
from IPy import IP
import requests
import json

class functions:

    def lista_paquetes(archivo_pcap):
        try:
            lista_paquetes = rdpcap(archivo_pcap)
            return lista_paquetes
        except:
            print("Error leyendo el archivo con la captura de trafico")

    def check_ip_publica_o_privada(direccion_ip):
        try: 
            ip = IP(direccion_ip)
            tipo = ip.iptype()
            return tipo
        except:
            print("hubo un error en el formato de")

    def numero_paquetes(lista_paquetes):
            numero_paquetes = len(lista_paquetes)
            return numero_paquetes
        
    def lista_ips_origen(lista_paquetes):
        lista_ips_origenes = []    
        for paquete in lista_paquetes:
            if 'IP' in paquete:
                try:
                    ip_origen = paquete['IP'].src
                    lista_ips_origenes.append(ip_origen)
                except:
                    print("Error extrayendo las IPs origen de la lista de paquetes!!!")
        lista_ips_origenes = list(set(lista_ips_origenes))
        return lista_ips_origenes

    def lista_ips_destino(lista_paquetes):
        lista_ips_destino = []
        for paquete in lista_paquetes:
            if 'IP' in paquete:
                try:
                    ip_destino = paquete['IP'].dst
                    lista_ips_destino.append(ip_destino)
                except:
                    print("Error extrayendo las IPs destinos de la lista de paquetes!!!")
                    break
        lista_ips_destino = list(set(lista_ips_destino))
        return lista_ips_destino

    def check_IP_abuseipdb(direccion_ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        API_key = 'a415ba70cfbb747a1c517552d41462540e6a0a35ac4ea462b6b2aa4588d0d4e41a9714f9e876f1db'
        query = {
            'ipAddress': direccion_ip
        }
        headers = {
            'Accept': 'application/json',
            'Key': API_key
        }
        response = requests.request(method='GET', url=url, headers=headers, params=query)    
        response = json.loads(response.text)
        lista_de_datos = []
        IP = response['data']['ipAddress']
        lista_de_datos.append(IP)
        score = response['data']['abuseConfidenceScore']
        lista_de_datos.append(score)
        codigo_pais = response['data']['countryCode']
        lista_de_datos.append(codigo_pais)
        total_reportes = response['data']['totalReports']
        lista_de_datos.append(total_reportes)        
        return lista_de_datos

    def help():
        print("""
     *********************************************************************************************************
     *                                                                                                       *
     *  ██╗  ██╗███████╗██╗     ██████╗                                                                      *
     *  ██║  ██║██╔════╝██║     ██╔══██╗                                                                     *
     *  ███████║█████╗  ██║     ██████╔╝                                                                     *
     *  ██╔══██║██╔══╝  ██║     ██╔═══╝                                                                      *
     *  ██║  ██║███████╗███████╗██║██╗██╗██╗                                                                 *
     *  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝╚═╝╚═╝                                                                 *
     *                                                                                                       *
     *  Uso del script:                                                                                      *
     *                                                                                                       *
     *  Este sript solo toma como parametro el archivo de captura de trafico en archivo pcap o pcapng.       *
     *                                                                                                       *
     *  >>>>>>>>>> [ python3 main.py captura_trafico.pcap ] <<<<<<<<<<<                                      *
     *                                                                                                       *        
     *********************************************************************************************************
        """)

    def main_banner():
        print("""
        ██╗ ██╗ ██╗   █████╗ ███╗   ██╗ █████╗ ██╗     ██╗███████╗██╗███████╗         
        ╚██╗╚██╗╚██╗ ██╔══██╗████╗  ██║██╔══██╗██║     ██║██╔════╝██║██╔════╝         
         ╚██╗╚██╗╚██╗███████║██╔██╗ ██║███████║██║     ██║███████╗██║███████╗         
         ██╔╝██╔╝██╔╝██╔══██║██║╚██╗██║██╔══██║██║     ██║╚════██║██║╚════██║         
        ██╔╝██╔╝██╔╝ ██║  ██║██║ ╚████║██║  ██║███████╗██║███████║██║███████║██╗██╗██╗
        ╚═╝ ╚═╝ ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝╚═╝╚═╝
        """)