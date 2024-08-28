from tkinter import *
from tkinter import messagebox
import base64
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt_notes():
    title = title_entry.get()
    message = my_text.get('1.0', END)
    master_secret = master_key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error", message="Please enter all info.")
    else:
        message_encrypted = encode(master_secret,message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            master_key_entry.delete(0, END)
            my_text.delete("1.0",END)

def decrypt_notes():
    message_encrypted =my_text.get("1.0", END)
    master_secret = master_key_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="error", message="please enter all info")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            my_text.delete("1.0",END)
            my_text.insert("1.0",decrypted_message)
        except:
            messagebox.showinfo(title="Error", message="Please enter Encrypted text")



window = Tk()
window.title("Secret Notes")
window.minsize(width=350, height=600)
window.config(padx=20,pady=30)

image = PhotoImage(file="top_secret.png")
image_label = Label(window,image=image)
image_label.pack()

label1 = Label(text="Enter your title",font=("Arial", "12", "normal"))
label1.config(pady=10)
label1.pack()

title_entry = Entry(width=20)
title_entry.pack()

label2 = Label(text="Enter your secret", font=("Arial", "12", "normal"))
label2.config(pady=10)
label2.pack()

my_text = Text(width=30,height=10)
my_text.pack()

label3 = Label(text="Enter master key",font=("Arial", "12", "normal"))
label3.config(pady=10)
label3.pack()

master_key_entry = Entry(width=20)
master_key_entry.pack()

save_button = Button(text="Save & Encrypt", command=save_and_encrypt_notes)
save_button.config(pady=3)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt_notes)
decrypt_button.config(pady=5)
decrypt_button.pack()


window.mainloop()
