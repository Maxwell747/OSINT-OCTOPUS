import customtkinter
from modules import (checkEmail, builtWith, zoomEye,
                     recon_ng, theHarvester, run_nmap)

customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('green')

root = customtkinter.CTk()
root.geometry('1000x900')


def login():
    print("test")


frame = customtkinter.CTkFrame(master=root)
frame.pack(padx=20, pady=60, fill='both', expand=True)

label = customtkinter.CTkLabel(master=frame, text='login system')
label.pack(pady=12, padx=10)

entry1 = customtkinter.CTkEntry(master=frame, placeholder_text='Username')
entry1. pack(pady=12, padx=10)
entry2 = customtkinter.CTkEntry(
    master=frame, placeholder_text='Password', show='*')
entry2. pack(pady=12, padx=10)

button = customtkinter.CTkButton(master=frame, text='Login', command=login)
button.pack(pady=12, padx=10)

checkbox = customtkinter.CTkCheckBox(master=frame, text='remember me')
checkbox.pack(pady=12, padx=10)


if __name__ == '__main__':
    print(run_nmap('scanme.nmap.org'))
    # root.mainloop()
