import re
import os
import tempfile
import pdfkit
import threading
import time
import uuid
from io import BytesIO
import requests
import logging
import configparser
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from PyPDF2 import PdfReader, PdfWriter

configuracion = configparser.ConfigParser()
configuracion.read('config/config.cfg')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('utils')

# Función principal que genera el PDF
def generar_pdf_documento(data, template_html):
    datos_procesados = {clave.upper(): valor for clave, valor in data.items()}

    marcadores_faltantes = detectar_marcadores_faltantes(template_html, datos_procesados)

    if marcadores_faltantes:
        raise ValueError(f"Marcadores faltantes: {', '.join(marcadores_faltantes)}")

    plantilla_html_procesada = re.sub(r'\[(.*?)](.*?)\[/\1\]', lambda match: reemplazar_marcador(match, datos_procesados), template_html)

    configuracion = pdfkit.configuration(wkhtmltopdf='./wkhtmltopdf/bin/wkhtmltopdf.exe')

    pdf_temp_body = generar_pdf_body(plantilla_html_procesada, configuracion)
    pdf_temp_header_footer = generar_pdf_encabezado_pie(plantilla_html_procesada, configuracion)

    pdf_writer_combinado = combinar_pdfs_con_marcas(pdf_temp_header_footer, pdf_temp_body)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_pdf_combinado:
        pdf_writer_combinado.write(temp_pdf_combinado)
        temp_pdf_combinado_path = temp_pdf_combinado.name

    pdf_con_marca_agua = agregar_marca_agua(temp_pdf_combinado_path, "marcas.pdf")
    
    uploads_dir = os.path.join(os.getcwd(), 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)

    usuario_id = data.get('ID_USUARIO', 'default_user')
    sGUID = str(uuid.uuid4()).replace("-", "")
    fecha_actual = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    nombre_generado = f"{usuario_id}-{sGUID}-{fecha_actual}.pdf"
    output_pdf_path = os.path.join(uploads_dir, nombre_generado)
    guardar_pdf(PdfReader(pdf_con_marca_agua), output_pdf_path)

    for pdf_file in [pdf_temp_header_footer, pdf_temp_body, pdf_con_marca_agua, temp_pdf_combinado_path]:
        os.remove(pdf_file)

    return output_pdf_path

# def eliminar_archivo_automaticamente(archivo_path):
#     time.sleep(1800)  # 1800 segundos = 30 minutos
#     if os.path.exists(archivo_path):
#         os.remove(archivo_path)
#         print(f"Archivo {archivo_path} eliminado automáticamente después de 30 minutos.")

def detectar_marcadores_faltantes(template_html, datos):
    """Detecta los marcadores no reemplazados en la plantilla."""
    marcadores_faltantes = []
    
    # Busca todos los marcadores en el formato [MARCADOR][/MARCADOR]
    marcadores_encontrados = re.findall(r'\[([A-Z_]+)]\[/\1]', template_html)
    
    for marcador in marcadores_encontrados:
        if marcador not in datos:
            # Si el marcador no está en los datos proporcionados, se considera faltante
            marcadores_faltantes.append(marcador)
    
    return marcadores_faltantes

def reemplazar_marcador(match, datos):
    clave = match.group(1)
    if clave == "TABLA":
        rows = ""
        count = 0
        MAX_ROWS_PER_PAGE = 30
        
        for fila in datos.get("TABLA", []):
            if count == MAX_ROWS_PER_PAGE:
                rows += "</table><div style='page-break-before: always;'></div><table>"
                count = 0
            row = "<tr>" + "".join([f"<td>{valor}</td>" for valor in fila]) + "</tr>"
            rows += row
            count += 1
        return rows
    elif clave in datos:
        return str(datos[clave])
    return match.group(0)

def generar_pdf_body(plantilla_html, configuracion):
    body_content = extraer_contenido_body(plantilla_html)
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_pdf:
        temp_pdf.write(pdfkit.from_string(body_content, None, configuration=configuracion, options={'encoding': 'utf-8'}))
    return temp_pdf.name

def extraer_contenido_body(plantilla_html):
    inicio = plantilla_html.find('<body>') + len('<body>')
    fin = plantilla_html.find('</body>')
    return plantilla_html[inicio:fin]

def generar_pdf_encabezado_pie(plantilla_html, configuracion):
    header = plantilla_html.split('<header>')[1].split('</header>')[0]
    footer = plantilla_html.split('<footer>')[1].split('</footer>')[0]
    blank_content = "<p></p>" * 50
    html_header_footer = f"<header>{header}</header>{blank_content}<footer>{footer}</footer>"

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_pdf:
        temp_pdf.write(pdfkit.from_string(html_header_footer, None, configuration=configuracion, options={'encoding': 'utf-8'}))
    return temp_pdf.name

def combinar_pdfs_con_marcas(pdf_header_footer, pdf_body):
    pdf_reader_header_footer = PdfReader(pdf_header_footer)
    pdf_reader_body = PdfReader(pdf_body)
    pdf_writer = PdfWriter()

    for i in range(len(pdf_reader_body.pages)):
        page_body = pdf_reader_body.pages[i]
        page_header_footer = pdf_reader_header_footer.pages[i % len(pdf_reader_header_footer.pages)]

        merged_page = page_header_footer.create_blank_page(width=page_body.mediabox.width, height=page_body.mediabox.height)
        merged_page.merge_page(page_header_footer)
        merged_page.merge_page(page_body)
        pdf_writer.add_page(merged_page)

    return pdf_writer

def agregar_marca_agua(pdf_input, marca_agua):
    pdf_reader_main = PdfReader(pdf_input)
    pdf_reader_watermark = PdfReader(marca_agua)
    pdf_writer = PdfWriter()

    watermark_page = pdf_reader_watermark.pages[0]

    for page in pdf_reader_main.pages:
        merged_page = watermark_page.create_blank_page(width=page.mediabox.width, height=page.mediabox.height)
        merged_page.merge_page(watermark_page)
        merged_page.merge_page(page)
        pdf_writer.add_page(merged_page)
    
    # No aplicamos encriptación aquí

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_pdf:
        pdf_writer.write(temp_pdf)
    
    return temp_pdf.name

def guardar_pdf(pdf_reader, filename, password=None):
    pdf_writer = PdfWriter()
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)
    if password:
        # Aplicar contraseña aquí al escritor antes de guardar el archivo final.
        pdf_writer.encrypt(user_password=password, use_128bit=True)
    with open(filename, 'wb') as output_pdf:
        pdf_writer.write(output_pdf)


# Validación de caracteres especiales
def contiene_caracteres_invalidos(texto):
    patron = re.compile(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ0-9 _\-,\.\\:\/\(\)]+$')
    return not patron.match(texto)

def reintentar_subida():
    log_path = os.path.join(os.getcwd(), 'logs', 'fallos_subida.log')

    if os.path.exists(log_path):
        with open(log_path, 'r') as log_file:
            archivos_pendientes = log_file.readlines()

        ruta_ws_upload_file = configuracion.get('GENERAL', 'ruta_ws_upload_file')
        token_ws_upload = configuracion.get('GENERAL', 'token_ws_upload')
        archivos_exitosos = []

        for linea in archivos_pendientes:
            partes = linea.split(' | ')
            nombre_archivo = partes[0].strip()
            archivo_local_path = partes[1].replace('Ruta local: ', '').strip()

            if os.path.exists(archivo_local_path):
                with open(archivo_local_path, 'rb') as pdf_file:
                    archivo_contenido = pdf_file.read()

                payload = {
                    'usuario': 'default_user',
                    'ruta': configuracion.get('GENERAL', 'ruta'),
                    'token': token_ws_upload,
                    'nombre_archivo': nombre_archivo
                }

                if subir_archivo_en_segundo_plano(ruta_ws_upload_file, archivo_contenido, payload, nombre_archivo, archivo_local_path):
                    archivos_exitosos.append(nombre_archivo)
            else:
                logger.warning(f"Archivo local {archivo_local_path} no encontrado.")

        # Actualizar log, removiendo archivos que se subieron exitosamente
        if archivos_exitosos:
            with open(log_path, 'w') as log_file:
                log_file.writelines([linea for linea in archivos_pendientes if linea.split(' | ')[0].strip() not in archivos_exitosos])
            logger.info("Log actualizado después de subir archivos exitosamente.")
            
def subir_archivo_en_segundo_plano(ruta_ws_upload_file, archivo_contenido, payload, nombre_archivo, archivo_local_path):
    try:
        archivo = {'file1': (nombre_archivo, BytesIO(archivo_contenido), 'application/octet-stream')}
        r = requests.post(ruta_ws_upload_file, files=archivo, data=payload)
        
        if r.json().get('success') == 1:
            if os.path.exists(archivo_local_path):
                os.remove(archivo_local_path)
                logger.info(f"Archivo {archivo_local_path} subido y eliminado localmente.")
            return True
        else:
            logger.error(f"Error al subir el archivo {nombre_archivo}.")
            escribir_log_fallo_subida(archivo_local_path, nombre_archivo)
            return False
    except requests.exceptions.RequestException as err:
        logger.error(f"Error de conexión al subir el archivo: {err}")
        escribir_log_fallo_subida(archivo_local_path, nombre_archivo)
        return False

def escribir_log_fallo_subida(archivo_local_path, nombre_archivo):
    log_path = os.path.join(os.getcwd(), 'logs', 'fallos_subida.log')
    if not os.path.exists(os.path.dirname(log_path)):
        os.makedirs(os.path.dirname(log_path))
    with open(log_path, 'a') as log_file:
        log_file.write(f"{nombre_archivo} | Ruta local: {archivo_local_path}\n")
    logger.info(f"Log registrado: No se pudo subir el archivo {nombre_archivo}")

def realizar_curl(url_base):
    try:
        response = requests.get(url_base, timeout=1)
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

def obtener_clave_encriptacion(key):
    if len(key) < 16:
        key = key.ljust(16, '0')
    elif len(key) > 32:
        key = key[:32]
    return key.encode('utf-8')

# Función para descifrar PDF
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

# Función para cifrar PDF
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