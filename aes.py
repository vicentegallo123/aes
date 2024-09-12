
# De los confines de la biblioteca `cryptography`, extraemos los saberes de los cifrados y otros secretos esotéricos.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os 

#librerias
#padding=elimina el relleno de los datos y los ajusta
#PBKDF2HMAC=Convierte una contraseña en una clave segura mediante
#hashes=Proporciona funciones de hash (como SHA-256)


def generar_clave(password, salt):
    kdf = PBKDF2HMAC(
       algorithm=hashes.SHA256(),  # Aquí empleamos la función hash SHA-256.
        length=32,  # La longitud de la clave será de 32 bytes (256 bits).
        salt=salt,  # Utilizamos el ingrediente secreto "sal" para hacer que la clave sea única.
        iterations=100000,  # Ejecutamos el proceso de derivación 100,000 veces para mayor seguridad.
        backend=default_backend()  # El backend provee las implementaciones criptográficas ne
    )
    return kdf.derive(password)  # Finalmente, la clave es derivada a partir de la contraseña.

# En esta función, `encriptar_archivo`, el objetivo es ocultar el contenido de un archivo, es decir, encriptarlo.
# La función toma un archivo de entrada, lo cifra utilizando una clave derivada de la contraseña,
# y luego deposita su versión encriptada en un nuevo archivo de salida.
def encriptar_archivo(archivo_entrada, archivo_salida, password):
    # Primero, se forja un nuevo "salt" (sal) aleatorio, de 16 bytes, para hacer que la clave sea única.
    salt = os.urandom(16)
    
    # Usamos la función anterior para generar la clave maestra a partir de la contraseña y el "salt".
    clave = generar_clave(password.encode(), salt)
    
    # Se invoca vector de inicialización (IV), necesario para el modo de cifrado CBC.
    iv = os.urandom(16)
    
    # Creamos el cifrador AES en modo CBC utilizando la clave y el IV generados.
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()  # Preparamos el cifrado.

    #  leemos el archivo original en su forma binaria.
    with open(archivo_entrada, 'rb') as archivo:
        datos = archivo.read()
    
    # Procedemos a rellenar los datos con padding (PKCS7) para que su tamaño sea adecuado para AES.
    padder = padding.PKCS7(128).padder()
    datos_padd = padder.update(datos) + padder.finalize()  
    
    # Ejecutamos el cifrado de los datos ya rellenados.
    datos_encriptados = encryptor.update(datos_padd) + encryptor.finalize()
    
    # Guardamos los datos encriptados en el archivo de salida, precedidos por el "salt" y el IV, posterior desencriptación.
    with open(archivo_salida, 'wb') as archivo:
        archivo.write(salt + iv + datos_encriptados)

# La siguiente función, `desencriptar_archivo`,
# Toma el archivo encriptado, descifra su contenido y lo deposita en otro archivo de salida.
def desencriptar_archivo(archivo_encriptado, archivo_salida, password):
    # Como paso inicial, leemos el archivo encriptado en modo binario.
    with open(archivo_encriptado, 'rb') as archivo:
        datos = archivo.read()

    # Recuperamos el "salt" y el IV, que fueron almacenados al inicio del archivo encriptado.
    salt = datos[:16]  # El "salt" ocupa los primeros 16 bytes.
    iv = datos[16:32]  # El IV ocupa los 16 bytes siguientes.
    datos_encriptados = datos[32:]  # El resto es el contenido encriptado.
    
    # Regeneramos la misma clave utilizando la contraseña y el "salt".
    clave = generar_clave(password.encode(), salt)
    
    # Creamos el descifrador AES utilizando la clave y el IV recuperados.
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Desciframos el contenido encriptado.
    datos_desencriptados = decryptor.update(datos_encriptados) + decryptor.finalize()
    
    # Quitamos el relleno (padding) para restaurar el archivo original.
    unpadder = padding.PKCS7(128).unpadder()
    datos_despad = unpadder.update(datos_desencriptados) + unpadder.finalize()
    
    # Finalmente, guardamos los datos descifrados en el archivo de salida.
    with open(archivo_salida, 'wb') as archivo:
        archivo.write(datos_despad)


# El archivo que será encriptado:
archivo_entrada = 'C:/Users/Admin/Desktop/hola.txt'
# El archivo resultante de la encriptación:
archivo_encriptado = 'C:/Users/Admin/Desktop/hola_encriptado.txt'
# El archivo donde se restaurará el contenido original:
archivo_desencriptado = 'C:/Users/Admin/Desktop/hola_desencriptado.txt'
# La contraseña utilizada para generar la clave mágica (clave AES).
password = 'mi_contraseña_segura'

# Aplicamos el cifrado al archivo.
encriptar_archivo(archivo_entrada, archivo_encriptado, password)
print(f'Archivo encriptado guardado en {archivo_encriptado}')

# Deshacemos el cifrado, devolviendo el archivo a su forma original.
desencriptar_archivo(archivo_encriptado, archivo_desencriptado, password)
print(f'Archivo desencriptado guardado en {archivo_desencriptado}')
