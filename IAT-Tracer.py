import pefile
import sys
import customtkinter
import os
from PIL import Image
from tkinter import filedialog
from tkinter import messagebox
from tkinter import StringVar
import pickle
import bz2

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

if getattr(sys, 'frozen', False):
    apidb_file = r"apidb.pickle"
    icon_file = r"iat-tracer.ico"
    application_path = os.path.dirname(sys.executable)
    params_file = os.path.join(application_path, "params.txt")
elif __file__:
    application_path = os.path.dirname(__file__)
    apidb_file = r"assets\apidb.pickle"
    icon_file = r"assets\iat-tracer.ico"
    params_file = "params.txt"

perf_flag = 0

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
            checkbox.configure(command=lambda: self.command(item))
        checkbox.grid(row=len(self.checkbox_list), column=0, pady=(0, 15),sticky='w')
        if item in set.union(app.clicked_traced_api_functions,app.clicked_imported_api_functions):
            checkbox.select()
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
        global perf_flag
        perf_flag = 1
        for checkbox in self.checkbox_list:
            if not checkbox.get():
                checkbox.toggle()
            if checkbox == self.checkbox_list[-1]:
                perf_flag = 0
                checkbox.toggle()
                checkbox.toggle()
            

    def deselect_all(self):
        global perf_flag
        perf_flag = 1
        for checkbox in self.checkbox_list:
            if checkbox.get():
                checkbox.toggle() 
            if checkbox == self.checkbox_list[-1]:
                perf_flag = 0
                checkbox.toggle()
                checkbox.toggle()
class App(customtkinter.CTk):

    imports = {}
    text_filter = ""
    api_functions = []
    filtered_api_functions = []
    loaded_functions = {}
    traced_api_functions = {}
    clicked_traced_api_functions = set()
    clicked_imported_api_functions = set()

    def resource_path(self,relative_path):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)

    def __init__(self):
        super().__init__()
        self.title("IAT-Tracer Plugin (By YoavLevi)")
        self.geometry("550x500")
        self.columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.choose_button = customtkinter.CTkButton(self, text="Choose a file", command=self.choose_button_callback)
        self.choose_button.grid(row=3, column=0, padx=10, pady=10, sticky="s")

        self.imported_scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=self.log_imported_choice_user_event,
                                                                 item_list=list(self.imports.keys()), height=300)
        self.imported_scrollable_checkbox_frame.grid(row=2, column=0, padx=0, pady=0)

        self.text_filter  = StringVar()
        resize_factor_textbox = customtkinter.CTkEntry(master    = self, 
                                    width      = 140,
                                    font       = customtkinter.CTkFont(family = "Segoe UI", size = 11, weight = "bold"),
                                    height     = 30,
                                    fg_color   = "#000000",
                                    textvariable = self.text_filter)
        resize_factor_textbox.grid(row=3, column=1, padx=0, pady=0)

        self.traced_scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=self.log_traced_choice_user_event,
                                                                 item_list=list(self.filtered_api_functions), height=300)
        self.traced_scrollable_checkbox_frame.grid(row=2, column=1, padx=0, pady=0)

        self.save_button = customtkinter.CTkButton(self, fg_color="#355E3B", text=f"save", command=self.save_button_callback)
        self.save_button.grid(row=4, column=0, padx=10, pady=10, sticky="s")

        self.select_all_button = customtkinter.CTkButton(self, text=f"Select all", command=self.select_all_button_callback)
        self.select_all_button.grid(row=0, column=0, padx=10, pady=10, sticky="s")

        self.deselect_all_button = customtkinter.CTkButton(self, text=f"Deselect all", command=self.deselect_all_button_callback)
        self.deselect_all_button.grid(row=1,  column=0, padx=10, pady=10, sticky="s")

        self.traced_select_all_button = customtkinter.CTkButton(self, text=f"Select all", command=self.traced_select_all_button_callback)
        self.traced_select_all_button.grid(row=0, column=1, padx=10, pady=10, sticky="s")

        self.deselect_all_button = customtkinter.CTkButton(self, text=f"Deselect all", command=self.traced_deselect_all_button_callback)
        self.deselect_all_button.grid(row=1,  column=1, padx=10, pady=10, sticky="s")

        self.import_tag_button = customtkinter.CTkButton(self, text=f"Import .tag file", command=self.import_tag_button_callback)
        self.import_tag_button.grid(row=4,  column=1, padx=10, pady=10, sticky="s")

        # self.filter_button = customtkinter.CTkButton(self, text=f"Filter", command=self.filter_button_callback)
        # self.filter_button.grid(row=4,  column=1, padx=10, pady=10, sticky="s")

        ifile = bz2.BZ2File(self.resource_path(apidb_file),'rb')
        self.loaded_functions = pickle.load(ifile)
        ifile.close()
        self.api_functions = self.loaded_functions.keys()

    def log_traced_choice_user_event(self, item):
        # print(f"traced choice clicked: {item}")
        if item in self.clicked_traced_api_functions:
            self.clicked_traced_api_functions.remove(item)
        else:
            self.clicked_traced_api_functions.add(item)

        if not perf_flag:
            self.imported_scrollable_checkbox_frame.destroy()
            self.imported_scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=self.log_imported_choice_user_event,
                                                                item_list=list(self.imports.keys()), height=300)
            self.imported_scrollable_checkbox_frame.grid(row=2, column=0, padx=0, pady=0)

        # print(self.clicked_traced_api_functions)

    def log_imported_choice_user_event(self, item):
        # print(f"imported choice clicked: {item}")
        if item in self.clicked_imported_api_functions:
            self.clicked_imported_api_functions.remove(item)
        else:
            self.clicked_imported_api_functions.add(item)
        if not perf_flag:
            self.filter_button_callback()
        # print(self.clicked_imported_api_functions)

    def browseFiles(self):
        try:
            filename = filedialog.askopenfilename(initialdir = os.path.dirname(os.path.abspath(__file__)),
                                                title = "Select a File",
                                                filetypes = (("PE files",".exe .dll"),("all files","*.*")))        
        except FileNotFoundError as err:
            return []
        return filename

    def browse_tag_files(self):
        try:
            filename = filedialog.askopenfilename(initialdir = os.path.dirname(os.path.abspath(__file__)),
                                                title = "Select a .tag File",
                                                filetypes = (("TAG files",".tag"),("all files","*.*")))        
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
        self.imported_scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=self.log_imported_choice_user_event,
                                                                 item_list=list(self.imports.keys()), height=300)
        self.imported_scrollable_checkbox_frame.grid(row=2, column=0, padx=0, pady=0)

        self.text_filter  = StringVar()
        resize_factor_textbox = customtkinter.CTkEntry(master    = self, 
                                    width      = 140,
                                    font       = customtkinter.CTkFont(family = "Segoe UI", size = 11, weight = "bold"),
                                    height     = 30,
                                    fg_color   = "#000000",
                                    textvariable = self.text_filter)
        resize_factor_textbox.grid(row=3, column=1, padx=0, pady=0)
        # print(self.text_filter.get())

        self.traced_scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=self.log_traced_choice_user_event,
                                                                 item_list=list(self.filtered_api_functions), height=300)
        self.traced_scrollable_checkbox_frame.grid(row=2, column=1, padx=0, pady=0)


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

        self.traced_select_all_button = customtkinter.CTkButton(self, text=f"Select all", command=self.traced_select_all_button_callback)
        self.traced_select_all_button.grid(row=0, column=1, padx=10, pady=10, sticky="s")

        self.deselect_all_button = customtkinter.CTkButton(self, text=f"Deselect all", command=self.traced_deselect_all_button_callback)
        self.deselect_all_button.grid(row=1,  column=1, padx=10, pady=10, sticky="s")

        self.import_tag_button = customtkinter.CTkButton(self, text=f"Import .tag file", command=self.import_tag_button_callback)
        self.import_tag_button.grid(row=4,  column=1, padx=10, pady=10, sticky="s")

        # self.filter_button = customtkinter.CTkButton(self, text=f"Filter", command=self.filter_button_callback)
        # self.filter_button.grid(row=4,  column=1, padx=10, pady=10, sticky="s")


    def save_button_callback(self):
        with open(params_file,'w',encoding='utf-8') as file:
            error_flag = 0
            # for func in set(self.imported_scrollable_checkbox_frame.get_checked_items() + self.traced_scrollable_checkbox_frame.get_checked_items()):
            for func in set.union(self.clicked_imported_api_functions,self.clicked_traced_api_functions):
                try:
                    file.write(f"{self.imports[func]};{func};{self.loaded_functions[func]}\n")
                except:
                    try:
                        file.write(f"{self.traced_api_functions[func]};{func};{self.loaded_functions[func]}\n")
                    except Exception as err:
                        error_flag = 1
                        print(f"API not Found: {err}")
                        continue
        if error_flag:
            self.show_warning_message()
        else:
            self.show_ok_message()

    def select_all_button_callback(self):
        self.imported_scrollable_checkbox_frame.select_all()

    def deselect_all_button_callback(self):
        self.imported_scrollable_checkbox_frame.deselect_all()

    def traced_select_all_button_callback(self):
        self.traced_scrollable_checkbox_frame.select_all()

    def traced_deselect_all_button_callback(self):
        self.traced_scrollable_checkbox_frame.deselect_all()

    def parse_unique_events(self,file):
        unique_lines = set(line.strip() for line in file.readlines()[1:] if ("." in line and "[" not in line))
        return unique_lines
        # return list(filter(lambda traced_line: traced_line.split(';')[1], file.readlines()[1:])) # TODO: unique lines, filter out lines without ".", filter out function names with "[]"

    def parse_tag_file(self,tag_filename):
        with open(tag_filename,'r',encoding='utf-8') as file:
            events = self.parse_unique_events(file)
            libs = [event.split('.')[0].split(';')[1] for event in events]
            funcs = [event.split('.')[1] for event in events]
            self.traced_api_functions = {funcs[i] : libs[i] for i in range(len(events))}


    def import_tag_button_callback(self):
        self.tag_filename = self.browse_tag_files()
        if self.tag_filename:
            self.parse_tag_file(self.tag_filename)
            self.import_tag_button.destroy()
            self.import_tag_button = customtkinter.CTkButton(self, fg_color="#A0522D", text=f"{self.tag_filename.split('/')[-1]}", command=self.import_tag_button_callback)
            self.import_tag_button.grid(row=4, column=1, padx=10, pady=10, sticky="s")
        else:
            return
        self.traced_scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=self.log_traced_choice_user_event,
                                                                 item_list=list(self.traced_api_functions), height=300)
        self.traced_scrollable_checkbox_frame.grid(row=2, column=1, padx=0, pady=0)
        # self.traced_scrollable_checkbox_frame.bind('<KeyRelease>', self.filter_button_callback)


    def filter_button_callback(self, event=[]):
        self.filtered_api_functions = list(filter(lambda function_name: self.text_filter.get().strip().casefold() in function_name.casefold(), self.traced_api_functions))

        self.traced_scrollable_checkbox_frame.destroy()
        self.traced_scrollable_checkbox_frame = ScrollableCheckBoxFrame(master=self, command=self.log_traced_choice_user_event,
                                                                item_list=list(self.filtered_api_functions), height=300)
        self.traced_scrollable_checkbox_frame.grid(row=2, column=1, padx=0, pady=0)
         

    def show_ok_message(self):
        messagebox.showinfo("Success", "File saved successfully.")

    def show_warning_message(self):
        messagebox.showinfo("Warning", "File saved successfully but some imports were not found in the Windows api DB.")


if __name__=='__main__':
    print(banner)
    customtkinter.set_appearance_mode("dark")
    app = App()
    app.iconbitmap(app.resource_path(icon_file))
    app.bind('<KeyRelease>', app.filter_button_callback)
    app.mainloop()