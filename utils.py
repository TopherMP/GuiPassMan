import json
import tkinter as tk
from tkinter import messagebox
import rsa
import os

if not os.path.exists("PassMan.pem"):
    # generate new rsa keys
    public, private = rsa.newkeys(2048)

    ## Write the keys in respective files
    #with open("public.pem","wb") as pub:
    #    pub.write(public.save_pkcs1())
    #with open("private.pem","wb") as priv:
    #    priv.write(private.save_pkcs1())

    with open("PassMan.pem","wb") as file:
        file.write(public.save_pkcs1()+private.save_pkcs1())

def encrypt(public_key, pswrd):
    encryptfile = rsa.encrypt(pswrd.encode(), public_key)
    return encryptfile

# Función para cargar datos desde un archivo JSON
def load_json(filename,data):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        with open(filename, 'w') as file: json.dump(data, file, indent=4)
        return {}

# Función para guardar datos en un archivo JSON
def save_json(filename, data):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo guardar el archivo '{filename}': {str(e)}")

# Función para verificar si los campos de entrada están vacíos
def validate_entries(*entries):
    return all(entry.get().strip() != "" for entry in entries)

def clean_entries(*entries):
    for entry in entries:
        entry.delete(0,tk.END)