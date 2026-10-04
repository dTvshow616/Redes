'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2020 EPS-UAM
'''

import argparse
import binascii
import logging
import signal
import sys
import time
from argparse import RawTextHelpFormatter

from rc1_pcap import *

ETH_FRAME_MAX = 1514 # Tamaño máximo a guardar de cada paquete para redes Ethernet
PROMISC = 1 # Promiscuo
NO_PROMISC = 0 # No promiscuo
TO_MS = 10 # Duración del timeout de lectura. Tiempo que se espera para leer varios paquetes en una misma transacción (polling)
num_paquete = 0 # Número del paquete actual
TIME_OFFSET = 30*60 


def signal_handler(nsignal,frame):
	"""
	Maneja la señal de Ctrl+C para terminar el programa
	- nsignal: el número de la señal
	- frame: el stack frame actual
	"""
	logging.info('Control C pulsado')
	if handle: # Si se ha abierto algún descriptor de fichero o interfaz, interrumpe su pcap_loop()
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data):
	"""
	Función de atención al paquete, se ejecuta por cada paquete leído o capturado
	- us: los datos auxiliares de usuario que se han pasado a pcap_loop <- Es None
	- header: objeto de tipo pcap_pkthdr que contiene la cabecera pcap del paquete leído o capturado
	- data: bytearray que contiene los datos del paquete en caso de éxito
	"""
	global num_paquete, start_sec, start_micr, end_sec, end_micr
	logging.info(f'Nuevo paquete de {header.len} bytes capturado en el timestamp UNIX {header.ts.tv_sec}.{header.ts.tv_usec}')
	num_paquete += 1
	
	# Guardar tiempos de captura del paquete
	if num_paquete == 1: # Es el primer paquete
		start_sec, start_micr = header.ts.tv_sec, header.ts.tv_usec
	end_sec, end_micr = header.ts.tv_sec, header.ts.tv_usec # Registrar el tiempo del último paquete recibido
		
	""" Imprimir los N primeros bytes en hexadecimal con 2 dígitos por Byte en mayúsculas (y separando cada Byte por 
	espacios en blanco), en líneas de  hasta 16 bytes """
	for i in range(0, min(len(data), args.nbytes), 16): # Partir los N primeros bytes en cachitos de 16 bytes
		data_line = binascii.hexlify(data[i:i+16]).decode() # Cachito a string hexadecimal
		string = ""
		for i in range(0, len(data_line), 2): # Para cada cachito añadir un 0x antes y juntarlos con espacios
			string = string + "0x" + data_line[i:i+2].upper() # Los dígitos son en mayúsculas
			if i != header.caplen-2: # Esto es para que no haya espacios extra al final
				string = string + " "
		print(string+'\n')
		
	""" Traza con nombre capturaNOIP.nombreitf.FECHA.pcap: En este fichero se almacenarán todos los paquetes cuyo 
	valor de los bytes 12 y 13 (comenzando a contar en 0) de la trama capturada SE corresponden con el valor 0x08 (byte 12) 
	y 0x06 (byte 13), respectivamente. Los que no coincidan se guardan en la traza  captura.nombreitf.FECHA.pcap"""
	# Almacenar los paquetes capturados enteros a través de la interfaz
	if args.interface and header.caplen == header.len:
		if hex(data[12]) == "0x8" and hex(data[13]) == "0x6":
			if pdumper1 != None:
				pcap_dump(pdumper1, header, data)
		else:
			if pdumper2 != None:
				pcap_dump(pdumper2, header, data)
		
		
if __name__ == "__main__":
	start_sec , start_micr, end_sec, end_micr = 0, 0, 0, 0 # Variables para los tiempos (segundos y microsegundos)
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz (o lee de fichero) y muestra la longitud y '
	+ 'timestamp de los npkts primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False, help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False, help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14, help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true', help='Activar Debug messages')
	parser.add_argument('--npkts', dest='npkts', type=int, default=-1, help='Número de paquetes a procesar') # Número de paquetes
	args = parser.parse_args() # Parseo de los argumentos

	# Activar el debug si se ha deseado por terminal
	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	# Comprobar que se pida recibir un paquete o una interfaz
	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	# Establecer el manejador de señales de tipo SIGINT (interrupción de teclado)
	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray() 	# Byte array para los mensajes de error
	handle = None 			# El descriptor PCAP del que queremos leer
	pdumper1 = None 		# El paquete apuntado por packet con cabecera handle en pcap_dump para traza 1
	pdumper2 = None 		# El paquete apuntado por packet con cabecera handle en pcap_dump para traza 2
	
	# Abrir la interfaz especificada para captura o la traza
	if args.tracefile: # Se pide abrir un fichero pcap
		handle = pcap_open_offline(args.tracefile, errbuf)
		if handle == None:
			logging.error(errbuf)
			
	elif args.interface: # Se pide abrir una interfaz
		handle = pcap_open_live(args.interface, -1, NO_PROMISC, TO_MS, errbuf)
		if handle == None:
			logging.error(errbuf)
	
		# Abrir un dumper para volcar el tráfico (si se ha especificado interfaz) 
		
		""" Traza 1: con nombre capturaNOIP.nombreitf.FECHA.pcap (donde FECHA será el tiempo actual UNIX en segundos y 
		nombreitf el nombre de la interfaz especificada) """
		# Abrir un descriptor de archivo pcap para paquetes Ethernet, guardando como máximo 1514 Bytes de cada paquete
		descr1 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX) 
		# Devuelve un objeto dumper que se usará para guardar paquetes en el archivo pcap con el nombre especificado
		pdumper1 = pcap_dump_open(descr1, 'capturaNOIP.' + args.interface + '.' + str(time.time()) + '.pcap') 
		
		""" Traza 2: con nombre captura.nombreitf. FECHA.pcap (donde FECHA será el tiempo actual UNIX en segundos y nombreitf 
		el nombre de la interfaz especificada) """
		# Abrir un descriptor de archivo pcap para paquetes Ethernet, guardando como máximo 1514 Bytes de cada paquete
		descr2 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX) 
		# Devuelve un objeto dumper que se usará para guardar paquetes en el archivo pcap con el nombre especificado
		pdumper2 = pcap_dump_open(descr2, 'captura.' + args.interface + '.' + str(time.time()) + '.pcap') 
	
	"""
	Se establece el pcap_loop para leer el tráfico de un archivo o interfaz
	- handle: el descriptor PCAP del que queremos leer (anteriormente creado)
	- args.npkts: número de paquetes a analizar
	- procesa_paquete: la función de atención al paquete, se ejecuta por cada paquete leído o capturado
	- None: variable auxiliar que sirve para pasar datos a la función de atención, en este caso prescindimos de ella
	"""
	if handle != None:
		ret = pcap_loop(handle, args.npkts, procesa_paquete, None)
		if ret == -1: 
			logging.error('Error al capturar un paquete')
		elif ret == -2:
			logging.debug('pcap_breakloop() llamado')
		elif ret == 0:
			logging.debug('No mas paquetes o limite superado')
		
	logging.info(f'{num_paquete} paquetes procesados')
	
	# Diferencia de tiempo entre el último y primer paquete capturado / de la traza (siempre que haya al menos 2 
	# paquetes, la diferencia será 0 en caso contrario) según la cabecera pcap
	if num_paquete < 2:
		end = 0
		start = 0
	else:
		end = end_sec + end_micr*(10**-6)
		start = start_sec + start_micr*(10**-6)
	logging.info(f'{end-start}s transcurridos entre el último y primer paquete')
	
	# Cerrar descriptores
	if handle != None:
		pcap_close(handle)
		
	# Si se ha creado un dumper cerrarlo
	if pdumper1 != None:
		pcap_dump_close(pdumper1)
 	
	if pdumper2 != None:
		pcap_dump_close(pdumper2)
