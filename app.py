from flask import Flask, request, jsonify, send_file
from utils import generar_pdf_documento, contiene_caracteres_invalidos
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from io import BytesIO
import requests
import logging
import configparser
import tempfile
from urllib.parse import urlparse
import threading

app = Flask(__name__)

configuracion = configparser.ConfigParser()
configuracion.read('config/config.cfg')

def escribir_log_fallo_subida(archivo_local_path, nombre_archivo):
    logs_dir = os.path.join(os.getcwd(), 'logs')
    
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    log_path = os.path.join(logs_dir, 'fallos_subida.log')
    
    logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s %(message)s')
    
    logging.info(f'Archivo no subido: {nombre_archivo} | Ruta local: {archivo_local_path}')
    print(f"Log registrado: No se pudo subir el archivo {nombre_archivo}")

def obtener_clave_encriptacion(key):
    if len(key) < 16:
        key = key.ljust(16, '0')  
    elif len(key) > 32:
        key = key[:32]  
    return key.encode('utf-8')

def cifrar_pdf(pdf_path, key):
    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()

    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(pdf_data) + padder.finalize()
    encrypted_pdf_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_pdf_path = pdf_path + ".enc"
    with open(encrypted_pdf_path, 'wb') as enc_file:
        enc_file.write(iv + encrypted_pdf_data)

    os.remove(pdf_path)

    return encrypted_pdf_path

def descifrar_pdf(encrypted_pdf_path, key):
    with open(encrypted_pdf_path, 'rb') as enc_file:
        iv = enc_file.read(16)  
        encrypted_pdf_data = enc_file.read()  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_pdf_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data

def subir_archivo_en_segundo_plano(ruta_ws_upload_file, archivo_contenido, payload, nombre_archivo, archivo_local_path):
    try:
        archivo = {'file1': (nombre_archivo + ".enc", BytesIO(archivo_contenido), 'application/octet-stream')}
        r = requests.post(ruta_ws_upload_file, files=archivo, data=payload)
        
        if r.json().get('success') == 1:
            respuesta_imagen = r.json().get('data')
            print(f"Archivo subido correctamente. URL: {respuesta_imagen}")
            
            if os.path.exists(archivo_local_path):
                os.remove(archivo_local_path)
                print(f"Archivo {archivo_local_path} eliminado después de la subida exitosa.")
        else:
            print("Error al subir el archivo")
            escribir_log_fallo_subida(archivo_local_path, nombre_archivo)
    
    except requests.exceptions.RequestException as err:
        print(f"Error al conectar con el servicio: {err}")
        escribir_log_fallo_subida(archivo_local_path, nombre_archivo)
        
def reintentar_subida():
    log_path = os.path.join(os.getcwd(), 'logs', 'fallos_subida.log')
    
    if os.path.exists(log_path):
        with open(log_path, 'r') as log_file:
            for linea in log_file:
                partes = linea.split(' | ')
                archivo_local_path = partes[1].replace('Ruta local: ', '').strip()
                nombre_archivo = partes[0].replace('Archivo no subido: ', '').strip()

                if os.path.exists(archivo_local_path):
                    ruta_ws_upload_file = configuracion.get('GENERAL', 'ruta_ws_upload_file')
                    base_url = obtener_base_url(ruta_ws_upload_file)
                    if realizar_curl(base_url):
                        print(f"Reintentando la subida del archivo {nombre_archivo}")
                        with open(archivo_local_path, 'rb') as pdf_file:
                            archivo_contenido = pdf_file.read()
                        token_ws_upload = configuracion.get('GENERAL', 'token_ws_upload') 
                        payload = {
                            'usuario': 'default_user',
                            'ruta': configuracion.get('GENERAL', 'ruta'),
                            'token': token_ws_upload,
                            'nombre_archivo': nombre_archivo
                        }
                        # Intenta subir nuevamente el archivo
                        subir_archivo_en_segundo_plano(ruta_ws_upload_file, archivo_contenido, payload, nombre_archivo, archivo_local_path)

        # Eliminar el log después de procesar las subidas
        os.remove(log_path)
        print("Log de fallos de subida eliminado.")
    else:
        print("No hay archivos pendientes de subida.")

        
def obtener_base_url(url_completa):
    from urllib.parse import urlparse
    parsed_url = urlparse(url_completa)
    return f"{parsed_url.scheme}://{parsed_url.netloc}"

def realizar_curl(url_base):
    try:
        response = requests.get(url_base, timeout=5)
        if response.status_code == 403:
            print("Servicio activo pero con acceso restringido.")
            return True
        response.raise_for_status()
        return True
    except requests.ConnectionError:
        print(f"No se pudo conectar a {url_base}. Servicio inactivo.")
        return False
    except requests.Timeout:
        print(f"Timeout al intentar conectar a {url_base}.")
        return False
    except requests.RequestException as err:
        print(f"Error al intentar conectar a {url_base}: {err}")
        return False



    
@app.route('/generate-pdf', methods=['POST'])
def generate_pdf():
    try:
        data = request.json.get('data')
        
        ruta_ws_upload_file = configuracion.get('GENERAL', 'ruta_ws_upload_file')
        base_url = obtener_base_url(ruta_ws_upload_file)

        servicio_activo = realizar_curl(base_url)

        for clave, valor in data.items():
            if isinstance(valor, str) and contiene_caracteres_invalidos(valor):
                return jsonify({"success": 2, "message": f"Se detectaron caracteres especiales no permitidos en el campo '{clave}'"}), 400

        template_html = request.json.get('template_html')
        output_pdf_path = generar_pdf_documento(data, template_html)

        encryption_key = obtener_clave_encriptacion(configuracion.get('GENERAL', 'encryption_key'))
        encrypted_pdf_path = cifrar_pdf(output_pdf_path, encryption_key)

        encrypted_pdf_size = os.path.getsize(encrypted_pdf_path)
        print(f"Tamaño del archivo cifrado antes de subir: {encrypted_pdf_size} bytes")

        with open(encrypted_pdf_path, 'rb') as pdf_file:
            archivo_contenido = pdf_file.read()

        token_ws_upload = request.json.get('token')
        usuario_id = data.get('ID_USUARIO', 'default_user')

        payload = {
            'usuario': usuario_id,
            'ruta': configuracion.get('GENERAL', 'ruta'),
            'token': token_ws_upload,
            'nombre_archivo': os.path.basename(encrypted_pdf_path)
        }

        if servicio_activo:
            # Si el servicio está activo, intentamos subir el archivo en segundo plano
            threading.Thread(target=subir_archivo_en_segundo_plano, args=(ruta_ws_upload_file, archivo_contenido, payload, os.path.basename(encrypted_pdf_path), encrypted_pdf_path), daemon=True).start()
        else:
            # Si el servicio no está activo, registramos el log para intentar subir el archivo luego
            escribir_log_fallo_subida(encrypted_pdf_path, os.path.basename(encrypted_pdf_path))
            print(f"Servicio de almacenamiento inactivo. El archivo {os.path.basename(encrypted_pdf_path)} se subirá más tarde.")

        return jsonify({
            "success": 1,
            "message": "OK",
            "nombre_archivo": os.path.basename(encrypted_pdf_path),
            "data": f"http://localhost:50055/uploads/{payload['ruta']}{os.path.basename(encrypted_pdf_path)}"
        }), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"success": 2, "message": "No se puede generar de forma automática y tiene que pasar a hacerse de forma manual", "error": str(e)}), 500


@app.route('/get-archivo', methods=['POST'])
def get_archivo():
    try:
        data = request.json
        ruta = data.get('ruta')
        nombre_archivo = data.get('nombre_archivo')

        url_get_archivo = configuracion.get('GENERAL', 'ruta_get_file')
        token = request.json.get('token')

        response = requests.post(url_get_archivo, json={
            "token": token,
            "ruta": ruta,
            "nombre_archivo": nombre_archivo 
        })

        if response.status_code == 200:
            encrypted_pdf_data = response.content

            print(f"Tamaño del archivo cifrado recibido: {len(encrypted_pdf_data)} bytes")

            with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as temp_enc:
                temp_enc.write(encrypted_pdf_data)
                temp_enc_path = temp_enc.name

            encryption_key = obtener_clave_encriptacion(configuracion.get('GENERAL', 'encryption_key'))
            decrypted_pdf_data = descifrar_pdf(temp_enc_path, encryption_key)

            os.remove(temp_enc_path)
            
            return send_file(
                BytesIO(decrypted_pdf_data),
                mimetype='application/pdf',
                as_attachment=True,
                download_name=nombre_archivo + ".pdf"
            )
        else:
            return jsonify(response.json()), response.status_code

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({
            "success": 2,
            "message": "Error al buscar el archivo",
            "error": str(e)
        }), 500



if __name__ == '__main__':
    app.run(debug=True)
