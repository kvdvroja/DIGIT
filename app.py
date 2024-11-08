from flask import Flask, request, jsonify, send_file
from utils import contiene_caracteres_invalidos,reintentar_subida, realizar_curl, subir_archivo_en_segundo_plano, obtener_clave_encriptacion, descifrar_pdf, cifrar_pdf, escribir_log_fallo_subida,generar_pdf_documento
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import time
from io import BytesIO
import requests
import logging
import configparser
import subprocess
import tempfile
from urllib.parse import urlparse
import threading

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) 

app = Flask(__name__)

configuracion = configparser.ConfigParser()
configuracion.read('config/config.cfg')

def ejecutar_verificator():
    """
    Ejecuta el script verificator.py como un subproceso.
    """
    try:
        print("Ejecutando verificator.py...")
        resultado = subprocess.run(['python', 'verificator.py'], capture_output=True, text=True)
        print(f"Salida de verificator.py:\n{resultado.stdout}")
        if resultado.stderr:
            print(f"Errores en verificator.py:\n{resultado.stderr}")
    except Exception as e:
        print(f"Error al ejecutar verificator.py: {e}")

def ejecutar_verificator_periodicamente():
    """
    Ejecuta verificator.py cada 30 minutos.
    """
    while True:
        ejecutar_verificator()
        print("Esperando 30 minutos para el siguiente ciclo...")
        time.sleep(120)  # 30 minutos

@app.route('/generate-pdf', methods=['POST'])
def generate_pdf():
    try:
        data = request.json.get('data')
        ruta_ws_upload_file = configuracion.get('GENERAL', 'ruta_ws_upload_file')
        base_url = f"{urlparse(ruta_ws_upload_file).scheme}://{urlparse(ruta_ws_upload_file).netloc}"
        servicio_activo = realizar_curl(base_url)

        if servicio_activo:
            reintentar_subida()
            
        for clave, valor in data.items():
            if isinstance(valor, str) and contiene_caracteres_invalidos(valor):
                return jsonify({"success": 2, "message": f"Se detectaron caracteres especiales no permitidos en el campo '{clave}'"}), 400

        # Aquí iría la lógica para generar el PDF
        template_html = request.json.get('template_html')
        output_pdf_path = generar_pdf_documento(data, template_html)
        encryption_key = obtener_clave_encriptacion(configuracion.get('GENERAL', 'encryption_key'))
        encrypted_pdf_path = cifrar_pdf(output_pdf_path, encryption_key)

        with open(encrypted_pdf_path, 'rb') as pdf_file:
            archivo_contenido = pdf_file.read()

        payload = {
            'usuario': data.get('ID_USUARIO', 'default_user'),
            'ruta': configuracion.get('GENERAL', 'ruta'),
            'token': request.json.get('token'),
            'nombre_archivo': os.path.basename(encrypted_pdf_path)
        }

        if servicio_activo:
            threading.Thread(target=subir_archivo_en_segundo_plano, args=(ruta_ws_upload_file, archivo_contenido, payload, os.path.basename(encrypted_pdf_path), encrypted_pdf_path), daemon=True).start()
        else:
            escribir_log_fallo_subida(encrypted_pdf_path, os.path.basename(encrypted_pdf_path))
            print(f"Servicio de almacenamiento inactivo. {os.path.basename(encrypted_pdf_path)} se subirá más tarde.")

        return jsonify({"success": 1, "message": "OK", "nombre_archivo": os.path.basename(encrypted_pdf_path)})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"success": 2, "message": "Fallo automático, ejecución manual requerida", "error": str(e)}), 500

@app.route('/get-archivo', methods=['POST'])
def get_archivo():
    try:
        data = request.json
        ruta = data.get('ruta')
        nombre_archivo = data.get('nombre_archivo')

        url_get_archivo = configuracion.get('GENERAL', 'ruta_get_file')
        token = request.json.get('token')

        base_url = f"{urlparse(url_get_archivo).scheme}://{urlparse(url_get_archivo).netloc}"
        servicio_activo = realizar_curl(base_url)

        if servicio_activo:
            response = requests.post(url_get_archivo, json={"token": token, "ruta": ruta, "nombre_archivo": nombre_archivo})
            if response.status_code == 200:
                encrypted_pdf_data = response.content
                encryption_key = obtener_clave_encriptacion(configuracion.get('GENERAL', 'encryption_key'))
                decrypted_pdf_data = descifrar_pdf(BytesIO(encrypted_pdf_data), encryption_key)
                return send_file(BytesIO(decrypted_pdf_data), mimetype='application/pdf', as_attachment=True, download_name=nombre_archivo + ".pdf")
            else:
                return jsonify(response.json()), response.status_code
        else:
            archivo_local_path = os.path.join(os.getcwd(), 'uploads', nombre_archivo)
            if os.path.exists(archivo_local_path):
                with open(archivo_local_path, 'rb') as enc_file:
                    encrypted_pdf_data = enc_file.read()
                encryption_key = obtener_clave_encriptacion(configuracion.get('GENERAL', 'encryption_key'))
                decrypted_pdf_data = descifrar_pdf(archivo_local_path, encryption_key)
                return send_file(BytesIO(decrypted_pdf_data), mimetype='application/pdf', as_attachment=True, download_name=nombre_archivo + ".pdf")
            else:
                return jsonify({"success": 2, "message": "Archivo no encontrado localmente"}), 404
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"success": 2, "message": "Error al buscar el archivo", "error": str(e)}), 500

if __name__ == '__main__':
    # Inicia un hilo para ejecutar verificator.py periódicamente
    print("Iniciando hilo para ejecutar verificator.py periódicamente.")
    hilo = threading.Thread(target=ejecutar_verificator_periodicamente, daemon=True)
    hilo.start()

    # Inicia el servidor Flask
    app.run(debug=True)
