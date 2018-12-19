# Necessary Imports
import tkinter as tk
from tkinter import Frame
from tkinter.ttk import Label
from tkinter.ttk import Entry
from tkinter.ttk import Radiobutton
from tkinter import IntVar
from tkinter import StringVar
from tkinter.ttk import Button
from tkinter.ttk import Progressbar
from tkinter import filedialog
from tkinter import messagebox
from threading import Thread
import endelogic

# Class to create the GUI of the program
class EncrypterDecrypterGUI:
    # Class Constructor
    def __init__(self):
        self.stop_all_thread = False
        self.encrypt_decrypt = None
        self.mode = True
        self.root = tk.Tk()
        self.createWindow()
        self.createUI()
        self.root.protocol('WM_DELETE_WINDOW', self.on_closing_window)
        self.root.iconbitmap('D:\Projects\FileEncrypterDecrypter\logo.ico')
        self.root.mainloop()

    # This class method will create the window
    def createWindow(self):
        self.root.resizable(height=False, width=False)
        self.root.title('File Encrypter Decrypter')

    # After creating the window this method will create the UI elements
    def createUI(self):
        tk.ttk.Style().configure('TButton', font=('Times New Roman', 16))
        tk.ttk.Style().configure('TRadiobutton', font=('Times New Roman', 16))
        tk.ttk.Style().configure('TLabel', font=('Times New Roman', 16))

        self.frame = Frame(self.root, width=500, height=400)

        self.radio_btn_var = IntVar()
        self.entry_var = StringVar()
        self.passw_var = StringVar()

        file_loc_label = Label(self.frame, text="File Location", font=('Times New Roman', 16))
        file_loc_label.grid(row=0, column=0, sticky='W', padx=10, pady=10)

        self.file_loc_box = Entry(self.frame, width=30, font=('Times New Roman', 16), textvariable=self.entry_var)
        self.file_loc_box.grid(row=0, column=1, padx=10, pady=10)
        self.file_loc_box.state(['readonly'])

        self.browse_btn = Button(self.frame, text='Browse...', command = self.onBrowseBtnClick)
        self.browse_btn.grid(row=0, column=2, padx=10, pady=10)

        pass_label = Label(self.frame, text="Password", font=('Times New Roman', 16))
        pass_label.grid(row=1, column=0, sticky='W', padx=10, pady=10)

        self.pass_box = Entry(self.frame, font=('Times New Roman', 16), width=30, show='*', textvariable=self.passw_var)
        self.pass_box.grid(row=1, column=1, padx=10, pady=10)

        self.encrypt_radio_btn = Radiobutton(self.frame, text="Encrypt File", variable=self.radio_btn_var, value=1,
                                             command=self.onSelectRadioBtn)
        self.encrypt_radio_btn.grid(row=2, column=0, padx=10, pady=10)

        self.decrypt_radio_btn = Radiobutton(self.frame, text='Decrypt File', variable=self.radio_btn_var, value=2,
                                             command=self.onSelectRadioBtn)
        self.decrypt_radio_btn.grid(row=2, column=1, padx=10, pady=10)
        self.radio_btn_var.set(1)

        self.ende_btn = Button(self.frame, text='Start Encryption', command=self.onStartEncryptionDecryptionBtnClick)
        self.ende_btn.grid(row=3, column=0, padx=10, pady=10)

        self.pbar = Progressbar(self.frame, orient=tk.HORIZONTAL, mode='determinate', length=300)
        self.pbar.grid(row=3, column=1, sticky='E')

        Label(self.frame, text='Created and Developed By Master Programmer (Deepank Pant)').grid(row=4, column=0, columnspan=3)

        self.frame.grid(row=0, column=0)

    # Event handler for the radio button
    def onSelectRadioBtn(self):
        if(self.radio_btn_var.get() == 1):
            self.ende_btn.configure(text='Start Encryption')
            self.mode = True
        elif self.radio_btn_var.get() == 2:
            self.ende_btn.configure(text='Start Decryption')
            self.mode = False

    # Event handler for the browse button
    def onBrowseBtnClick(self):
        self.file_loc = filedialog.askopenfilename(title='Select File for Encryption')
        self.entry_var.set(self.file_loc)

    # Event handler for the start encryption button
    def onStartEncryptionDecryptionBtnClick(self):
        if self.constraints():
            self.ende_btn.state(['disabled'])
            if self.encrypt_decrypt is None:
                self.encrypt_decrypt = endelogic.EncrypterDecrypter(self.file_loc, self.pass_box.get())
            if self.mode:
                if not self.checkFile():
                    self.encrypt_decrypt.updateKeyFileLoc(self.file_loc, self.pass_box.get())
                    self.encrypt_decrypt.startEncryption()
                    Thread(target=self.updateProgressBar).start()
                else:
                    messagebox.showerror('Message From File Encrypter Decrypter', 'File is Already Encrypted')
                    self.ende_btn.state(['!disabled'])
            else:
                if self.checkFile():
                    self.encrypt_decrypt.updateKeyFileLoc(self.file_loc, self.pass_box.get())
                    self.encrypt_decrypt.startDecryption()
                    Thread(target=self.updateProgressBar).start()
                else:
                    messagebox.showerror('Message From File Encrypter Decrypter', 'File is not Encrypted')
                    self.ende_btn.state(['!disabled'])

    # Thread to update the progress bar to show the progress and
    # all the necessary messages to the user
    def updateProgressBar(self):
        while self.encrypt_decrypt.op_running and (not self.stop_all_thread):
            if self.encrypt_decrypt.percent_complete - self.pbar['value'] > 0:
                self.pbar['value'] = self.encrypt_decrypt.percent_complete
            if self.pbar['value'] >=99.99:
                if self.mode:
                    messagebox.showinfo('Message From File Encrypter Decrypter', 'Encryption Complete')
                else:
                    messagebox.showinfo('Message From File Encrypter Decrypter', 'Decryption Complete')
                self.pbar['value'] = 0
                self.entry_var.set('')
                self.passw_var.set('')
                self.ende_btn.state(['!disabled'])
            if self.encrypt_decrypt.pass_mismatch:
                messagebox.showerror('Message From File Encrypter Decrypter', 'Wrong Password Entered')
                self.ende_btn.state(['!disabled'])
                self.entry_var.set('')
                self.passw_var.set('')
                self.encrypt_decrypt.delFile()
                break
            if self.encrypt_decrypt.general_error:
                messagebox.showerror('Message From File Encrypter Decrypter', self.encrypt_decrypt.error_msg)
                self.ende_btn.state(['!disabled'])
                self.entry_var.set('')
                self.passw_var.set('')
                self.encrypt_decrypt.delFile()
                break

    # Constraints required for the safe operation
    def constraints(self):
        if(self.file_loc_box.get() == ''):
            messagebox.showerror('Message From File Encrypter Decrypter', 'You have to select the file')
            return False
        if(self.pass_box.get() == ''):
            messagebox.showerror('Message From File Encrypter Decrypter', 'Password Field cannot be set empty')
            return False
        return True

    # Event handler for the closing window event
    def on_closing_window(self):
        self.stop_all_thread = True
        if self.encrypt_decrypt is not None:
            self.encrypt_decrypt.stop_all_thread = True
        self.root.destroy()

    # Check whether the file is encrypted or decrypted
    def checkFile(self):
        if('.crypto256' in self.file_loc):
            return True
        return False
