import re
import os
import tempfile
import pdfkit
import threading
import time
import uuid
import datetime
from PyPDF2 import PdfReader, PdfWriter

# Función principal que genera el PDF
def generar_pdf_documento(data, template_html):
    # Convertimos las claves del JSON en mayúsculas
    datos_procesados = {clave.upper(): valor for clave, valor in data.items()}

    # Reemplazamos los marcadores en la plantilla HTML
    plantilla_html_procesada = re.sub(r'\[(.*?)](.*?)\[/\1\]', lambda match: reemplazar_marcador(match, datos_procesados), template_html)

    # Configuración de pdfkit
    configuracion = pdfkit.configuration(wkhtmltopdf='./wkhtmltopdf/bin/wkhtmltopdf.exe')

    # Generamos el PDF y lo guardamos en un archivo temporal
    pdf_temp_body = generar_pdf_body(plantilla_html_procesada, configuracion)
    pdf_temp_header_footer = generar_pdf_encabezado_pie(plantilla_html_procesada, configuracion)

    pdf_writer_combinado = combinar_pdfs_con_marcas(pdf_temp_header_footer, pdf_temp_body)

    # Creamos un archivo temporal para guardar el PDF final
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_pdf_combinado:
        pdf_writer_combinado.write(temp_pdf_combinado)
        temp_pdf_combinado_path = temp_pdf_combinado.name

    # Generar el PDF final con marca de agua (si es necesario)
    pdf_con_marca_agua = agregar_marca_agua(temp_pdf_combinado_path, "marcas.pdf")
    
    uploads_dir = os.path.join(os.getcwd(), 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)

    # Ruta del archivo PDF final que será retornado
    usuario_id = data.get('ID_USUARIO', 'default_user')
    sGUID = str(uuid.uuid4()).replace("-", "")
    fecha_actual = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    # Generar el nombre del archivo
    nombre_generado = f"{usuario_id}-{sGUID}-{fecha_actual}.pdf"
    output_pdf_path = os.path.join(uploads_dir, nombre_generado)
    guardar_pdf(PdfReader(pdf_con_marca_agua), output_pdf_path)

    # Limpiar archivos temporales
    for pdf_file in [pdf_temp_header_footer, pdf_temp_body, pdf_con_marca_agua, temp_pdf_combinado_path]:
        os.remove(pdf_file)
        
    threading.Thread(target=eliminar_archivo_automaticamente, args=(output_pdf_path,), daemon=True).start()

    return output_pdf_path


def eliminar_archivo_automaticamente(archivo_path):
    time.sleep(1800)  # 1800 segundos = 30 minutos
    if os.path.exists(archivo_path):
        os.remove(archivo_path)
        print(f"Archivo {archivo_path} eliminado automáticamente después de 30 minutos.")

# Funciones auxiliares
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
        return datos[clave]
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
    patron = re.compile(r'^[a-zA-Z0-9 _\-,\.\\:\/]+$')
    return not patron.match(texto)
