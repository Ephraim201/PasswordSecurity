import tkinter as tk
import re
from tkinter import messagebox
from tkinter import *
import secrets
import string
from PIL import Image, ImageTk, ImageSequence

#------- FUNCIONES -------

def check_password_security(password):
    length_check = len(password) >= 8
    uppercase_check = any(c.isupper() for c in password)
    lowercase_check = any(c.islower() for c in password)
    digit_check = any(c.isdigit() for c in password)
    special_check = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

    criteria_not_met = []
    if not length_check:
        criteria_not_met.append("debe tener al menos 8 caracteres")
    if not uppercase_check:
        criteria_not_met.append("debe contener al menos una letra mayúscula")
    if not lowercase_check:
        criteria_not_met.append("debe contener al menos una letra minúscula")
    if not digit_check:
        criteria_not_met.append("debe contener al menos un número")
    if not special_check:
        criteria_not_met.append("debe contener al menos un carácter especial: !@#$%^&*(),.?\":{}|<>")

    # Verifica los criterios
    if all([length_check, uppercase_check, lowercase_check, digit_check, special_check]):
        return "Segura"
    else:
        return "No segura", criteria_not_met

def img_visible():
    global imagen_actual
    if imagen_actual == imagenOjo:
        toggle_button.config(image=imagenOjoC)
        imagen_actual = imagenOjoC
    else:
        toggle_button.config(image=imagenOjo)
        imagen_actual = imagenOjo

def toggle_password_visibility():
        
    current_show_value = password_entry.cget("show")
    if current_show_value == "":
        password_entry.config(show="*")
    else:
        password_entry.config(show="")

def save_password():
    password = password_entry.get()
    name = name_entry.get()  # Obtener el nombre ingresado por el usuario
    if check_password_security(password) == "Segura":
        with open("contrasenas_guardadas.txt", "a") as file:
            file.write(f"{name}: {password}\n")
        messagebox.showinfo("Contraseña Guardada", "La contraseña segura se ha guardado en el archivo 'contrasenas_guardadas.txt'.")

def check_password():
    password = password_entry.get()
    result = check_password_security(password)
    if result == "Segura":
        password_status.config(text="Contraseña segura", fg="green")
        save_button.config(state="normal")  # Hacer el botón de guardar interactivo
    else:
        security_status, criteria_not_met = result
        criteria_text = "\n".join(criteria_not_met)
        message = f"Contraseña no segura. Le falta lo siguiente:\n{criteria_text}"
        password_status.config(text=message, fg="red")
        save_button.config(state="disabled")  # Deshabilitar el botón de guardar

def generate_random_password():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(12))  # Generar una contraseña de 12 caracteres aleatorios
        if check_password_security(password) == "Segura":
            password_entry.delete(0, "end")  # Borrar cualquier contraseña anterior
            password_entry.insert(0, password)  # Insertar la nueva contraseña en el campo de entrada
            break

def actualizar_gif():
    global indice_fotograma
    try:
        # Muestra el siguiente fotograma del GIF
        imagen_actual = lista_imagenes[indice_fotograma]
        etiqueta.config(image=imagen_actual)
        indice_fotograma = (indice_fotograma + 1) % len(lista_imagenes)
        root.after(100, actualizar_gif)  # Llama a la función cada 100 milisegundos para una animación suave
    except Exception as e:
        print(e)

#-------- FRONTEN ----------

root = tk.Tk()
root.title("Verificador/Generador de Contraseñas")
root.geometry("550x550")

canvas = tk.Canvas(root, width=550, height=550)
canvas.pack()

imagen_fondo_original = PhotoImage(file="img\\sonic.png")
ancho_deseado = 900  # Cambia esto al ancho deseado
alto_deseado = 650   # Cambia esto al alto deseado
imagen_fondo = imagen_fondo_original.subsample(int(imagen_fondo_original.width() / ancho_deseado), int(imagen_fondo_original.height() / alto_deseado))

# Colocar la imagen redimensionada en el Canvas
canvas.create_image(0, 0, anchor=tk.NW, image=imagen_fondo)

# Crea una etiqueta y un campo de entrada para el nombre de la contraseña
name_label = tk.Label(root, text="Nombre de la contraseña:")
name_entry = tk.Entry(root)
canvas.create_window(150, 100, window=name_label)
canvas.create_window(350, 100, window=name_entry)

# Crea una etiqueta y un campo de entrada para la contraseña
password_label = tk.Label(root, text="Contraseña:")
password_entry = tk.Entry(root, show="*")
canvas.create_window(150, 130, window=password_label)
canvas.create_window(350, 130, window=password_entry)

# ----- Boton visible contraseña 
imagenOjo = PhotoImage(file="img\\3.png")
imagenOjoC = PhotoImage(file="img\\2.png")
imagen_actual = imagenOjo
toggle_button = tk.Button(root, image=imagen_actual, command=lambda:(toggle_password_visibility(),img_visible()))
canvas.create_window(447, 131, window=toggle_button)

# Crea una etiqueta para mostrar el estado de la contraseña
password_status = tk.Label(root, text="", fg="red")
canvas.create_window(280, 490, window=password_status)

# Crea un botón para verificar la contraseña
check_button = tk.Button(root, text="Verificar", command=check_password)
canvas.create_window(150, 165, window=check_button)

# Crea un botón para guardar la contraseña segura
save_button = tk.Button(root, text="Guardar Contraseña Segura", command=save_password, state="disabled")
canvas.create_window(350, 165, window=save_button)

imagenDado = PhotoImage(file="img\\dado.png")
imagen_Dado_redimensionada = imagenDado.subsample(14, 14)
generate_button = tk.Button(root, image= imagen_Dado_redimensionada, command=generate_random_password)
canvas.create_window(250, 131, window=generate_button)

#------------ OTROS --------------
imagen = Image.open("img\\penguin.gif")
lista_imagenes = [ImageTk.PhotoImage(imagen_frame) for imagen_frame in ImageSequence.Iterator(imagen)]

# Crear una etiqueta (Label) para mostrar el GIF
etiqueta = tk.Label(root)
canvas.create_window(280, 300, window=etiqueta)

# Iniciar la animación
indice_fotograma = 0
actualizar_gif()

#------------ INICIAR ----------- 
root.mainloop()
