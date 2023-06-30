import pefile
import json
import customtkinter
import os
from PIL import Image
from tkinter import filedialog
from tkinter import messagebox

banner = """

██╗░█████╗░████████╗░░░░░░████████╗██████╗░░█████╗░░█████╗░███████╗██████╗░
██║██╔══██╗╚══██╔══╝░░░░░░╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
██║███████║░░░██║░░░█████╗░░░██║░░░██████╔╝███████║██║░░╚═╝█████╗░░██████╔╝
██║██╔══██║░░░██║░░░╚════╝░░░██║░░░██╔══██╗██╔══██║██║░░██╗██╔══╝░░██╔══██╗
██║██║░░██║░░░██║░░░░░░░░░░░░██║░░░██║░░██║██║░░██║╚█████╔╝███████╗██║░░██║
╚═╝╚═╝░░╚═╝░░░╚═╝░░░░░░░░░░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚══════╝╚═╝░░╚═╝

╔══╗─────╔╗──╔╗───────╔╗
║╔╗║─────║╚╗╔╝║───────║║
║╚╝╚╦╗─╔╗╚╗╚╝╔╩═╦══╦╗╔╣║──╔══╦╗╔╦╗
║╔═╗║║─║║─╚╗╔╣╔╗║╔╗║╚╝║║─╔╣║═╣╚╝╠╣
║╚═╝║╚═╝║──║║║╚╝║╔╗╠╗╔╣╚═╝║║═╬╗╔╣║
╚═══╩═╗╔╝──╚╝╚══╩╝╚╝╚╝╚═══╩══╝╚╝╚╝
────╔═╝║
────╚══╝
"""

apidb_file = r"assets\apidb.json"
params_file = "params.txt"

# imports = {}

class ScrollableCheckBoxFrame(customtkinter.CTkScrollableFrame):
    def __init__(self, master, item_list, command=None, **kwargs):
        super().__init__(master, **kwargs)

        self.command = command
        self.checkbox_list = []
        for i, item in enumerate(item_list):
            self.add_item(item)

    def add_item(self, item):
        checkbox = customtkinter.CTkCheckBox(self, text=item)
        if self.command is not None:
            checkbox.configure(command=self.command)
        checkbox.grid(row=len(self.checkbox_list), column=0, pady=(0, 15),sticky='w')
        self.checkbox_list.append(checkbox)

    def remove_item(self, item):
        for checkbox in self.checkbox_list:
            if item == checkbox.cget("text"):
                checkbox.destroy()
                self.checkbox_list.remove(checkbox)
                return

    def get_checked_items(self):
        return [checkbox.cget("text") for checkbox in self.checkbox_list if checkbox.get() == 1]
    
    def select_all(self):
        for checkbox in self.checkbox_list:
            checkbox.select()   

    def deselect_all(self):
        for checkbox in self.checkbox_list:
            checkbox.deselect()  

class App(customtkinter.CTk):

    imports = {}

    def __init__(self):
        super().__init__()
        self.title("IAT-Tracer Plugin (By YoavLevi)")
        self.geometry("450x500")
        self.columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.choose_button = customtkinter.CTkButton(self, text="Choose a file", command=self.choose_button_callback)
        self.choose_button.grid(row=1, column=0, padx=10, pady=10, sticky="s")

    def browseFiles(self):
        try:
            filename = filedialog.askopenfilename(initialdir = os.path.dirname(os.path.abspath(__file__)),
                                                title = "Select a File",
                                                filetypes = (("PE files",".exe .dll"),("all files","*.*")))        
        except FileNotFoundError as err:
            return []
        return filename

    def show_choices(self,filename):
        pe =  pefile.PE(filename)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    dll = entry.dll.decode('utf-8').lower().split('.')[0]
                    name = imp.name.decode('utf-8')
                    self.imports[name]=dll
        # create scrollable checkbox frame
        self.scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=None,
                                                                 item_list=list(self.imports.keys()), height=300)
        self.scrollable_checkbox_frame.grid(row=2, column=0, padx=0, pady=0)

    def choose_button_callback(self):
        self.filename = self.browseFiles()
        if self.filename:
            self.show_choices(self.filename)
        else:
            return

        self.choose_button.destroy()
        self.choose_button = customtkinter.CTkButton(self, fg_color="#A0522D", text=f"{self.filename.split('/')[-1]}", command=self.choose_button_callback)
        self.choose_button.grid(row=3, column=0, padx=10, pady=10, sticky="s")

        self.save_button = customtkinter.CTkButton(self, fg_color="#355E3B", text=f"save", command=self.save_button_callback)
        self.save_button.grid(row=4, column=0, padx=10, pady=10, sticky="s")

        self.select_all_button = customtkinter.CTkButton(self, text=f"Select all", command=self.select_all_button_callback)
        self.select_all_button.grid(row=0, column=0, padx=10, pady=10, sticky="s")

        self.deselect_all_button = customtkinter.CTkButton(self, text=f"Deselect all", command=self.deselect_all_button_callback)
        self.deselect_all_button.grid(row=1,  column=0, padx=10, pady=10, sticky="s")

    def save_button_callback(self):
        with open(apidb_file, "r") as read_file:
            loaded_functions = json.load(read_file)
            with open(params_file,'w',encoding='utf-8') as file:
                error_flag = 0
                for func in self.scrollable_checkbox_frame.get_checked_items():
                    try:
                        file.write(f"{self.imports[func]};{func};{loaded_functions[func]}\n")
                    except Exception as err:
                        error_flag = 1
                        print(err)
                        continue
            if error_flag:
                self.show_warning_message()
            else:
                self.show_ok_message()

    def select_all_button_callback(self):
        self.scrollable_checkbox_frame.select_all()

    def deselect_all_button_callback(self):
        self.scrollable_checkbox_frame.deselect_all()

    def show_ok_message(self):
        messagebox.showinfo("Success", "File saved successfully.")

    def show_warning_message(self):
        messagebox.showinfo("Warning", "File saved successfully but some imports were not found in the Windows api DB.")


if __name__=='__main__':
    print(banner)
    customtkinter.set_appearance_mode("dark")
    app = App()
    app.iconbitmap(r"assets\iat-tracer.ico")
    app.mainloop()
