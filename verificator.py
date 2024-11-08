import time
from utils import reintentar_subida, realizar_curl
from urllib.parse import urlparse
import configparser

configuracion = configparser.ConfigParser()
configuracion.read('config/config.cfg')

def verificar_y_reintentar():
    url_subida = configuracion.get('GENERAL', 'ruta_ws_upload_file')
    base_url = f"{urlparse(url_subida).scheme}://{urlparse(url_subida).netloc}"

    while True:
        if realizar_curl(base_url):
            print("Servicio Activo, subiendo...")
            reintentar_subida()
        else:
            print("Esperando a que el servicio de subida esté activo...")
        time.sleep(120)  # 30 minutos

if __name__ == "__main__":
    verificar_y_reintentar()
