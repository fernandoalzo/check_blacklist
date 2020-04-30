import sys
from functions import functions
#print("numero de argumentos: " + str(len(sys.argv)))
#print("argumentos: " + str(sys.argv))


if __name__ == "__main__":
    numero_argumentos = len(sys.argv)    
    if numero_argumentos == 2:
        print("es hora de usar la herramienta")
        captura_trafico = sys.argv[1]
        lista_paquetes = functions.lista_paquetes(captura_trafico)
        numero_paquetes = functions.numero_paquetes(lista_paquetes)
        print(numero_paquetes)
        ips_destino = functions.lista_ips_destino(lista_paquetes)
        print(ips_destino)

    else:
        print("Error de uso de la herramienta")