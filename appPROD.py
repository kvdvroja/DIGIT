from flask import Flask, request, jsonify, send_file
from utils import generar_pdf_documento, contiene_caracteres_invalidos
import os
from io import BytesIO
import requests
import configparser

app = Flask(__name__)

configuracion = configparser.ConfigParser()
configuracion.read('config/config.cfg')

def subir_archivo_en_segundo_plano(ruta_ws_upload_file, archivo, payload):
    try:
        r = requests.post(ruta_ws_upload_file, files=archivo, data=payload)
        if r.json().get('success') == 1:
            respuesta_imagen = r.json().get('data')
            print(f"Archivo subido correctamente. URL: {respuesta_imagen}")
        else:
            print("Error al subir el archivo")
    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print("OOps: Something Else", err)

@app.route('/generate-pdf', methods=['POST'])
def generate_pdf():
    try:
        data = request.json.get('data')
        
        # Validamos si hay caracteres inválidos en el contenido
        for clave, valor in data.items():
            if isinstance(valor, str) and contiene_caracteres_invalidos(valor):
                return jsonify({"success": 2, "message": f"Se detectaron caracteres especiales no permitidos en el campo '{clave}'"}), 400

        template_html = request.json.get('template_html')
        output_pdf_path, nombre_generado = generar_pdf_documento(data, template_html)
        
        # Configuración para el upload del archivo
        ruta_ws_upload_file = configuracion['GENERAL']['ruta_ws_upload_file']
        hash_token_ws_upload_file = configuracion['GENERAL']['hash_token_ws_upload_file']
        token_ws_upload = request.json.get('token')
        usuario_id = data.get('ID_USUARIO', 'default_user')  # Default en caso de que no esté presente

        payload = {
            'usuario': usuario_id,
            'ruta': configuracion['GENERAL']['ruta'],
            'token': token_ws_upload,
            'nombre_archivo': nombre_generado
        }
        
        with open(output_pdf_path, 'rb') as pdf_file:
            archivo = {'file1': pdf_file}
            
            try:
                r = requests.post(ruta_ws_upload_file, files=archivo, data=payload)
                
                if r.json().get('success') == 1:
                    respuesta_imagen = r.json().get('data')
                    print(f"Archivo subido correctamente. URL: {respuesta_imagen}")
                    
                    nombre_archivo = os.path.basename(respuesta_imagen)

                    return jsonify({
                        "success": 1,
                        "message": "OK",
                        "data": respuesta_imagen,
                        "nombre_archivo": nombre_archivo
                    }), 200
                else:
                    print("Error al subir el archivo")
                    return jsonify({"success": 2, "message": "Error al subir el archivo"}), 500
                    
            except requests.exceptions.HTTPError as errh:
                print("Http Error:", errh)
                return jsonify({"success": 2, "message": "Http Error"}), 500
            except requests.exceptions.ConnectionError as errc:
                print("Error Connecting:", errc)
                return jsonify({"success": 2, "message": "Error de conexión"}), 500
            except requests.exceptions.Timeout as errt:
                print("Timeout Error:", errt)
                return jsonify({"success": 2, "message": "Error de tiempo de espera"}), 500
            except requests.exceptions.RequestException as err:
                print("OOps: Something Else", err)
                return jsonify({"success": 2, "message": "Error desconocido"}), 500

        # Si todo fue bien, enviamos el PDF generado
        return send_file(output_pdf_path, as_attachment=True)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"success": 2, "message": "No se puede generar de forma automática y tiene que pasar a hacerse de forma manual", "error": str(e)}), 500

@app.route('/get-archivo', methods=['POST'])
def get_archivo():
    try:
        # Obtener los datos del JSON recibido
        data = request.json
        #token = data.get('token')
        ruta = data.get('ruta')
        nombre_archivo = data.get('nombre_archivo')
        
        url_get_archivo = configuracion["GENERAL"]["ruta_get_file"]
        token = request.json.get('token')

        response = requests.post(url_get_archivo, json={
            "token": token,
            "ruta": ruta,
            "nombre_archivo": nombre_archivo
        })

        if response.status_code == 200:
            mime_type = response.headers['Content-Type']
            archivo_bytes = BytesIO(response.content)

            return send_file(archivo_bytes, mimetype=mime_type, as_attachment=True, download_name=nombre_archivo)
        
        else:
            return jsonify(response.json()), response.status_code

    except Exception as e:
        return jsonify({"success": 2, "message": "Error al buscar el archivo", "error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
