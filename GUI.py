import threading
import time
import tkinter
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
from tkinter import ttk
import json
import nmap
import mysql.connector
from JsonParsing import NmapParse

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="root",
    database="cpeiotdb"
)

mycursor = mydb.cursor()


class CPE:
    def __init__(self, name_of_cpe, cve_list, desc_list):
        self.cpe_name = name_of_cpe
        self.cve_col = cve_list
        self.desc_col = desc_list

class UI:

    def __init__(self, root):
        self.root = root
        self.root.title("IOT VULNERABILITY SYSTEM")
        self.root.geometry("1600x900+0+0")
        self.root.config(bg="white")
        self.bg = ImageTk.PhotoImage(file="images/main.png")
        bg = Label(self.root, image=self.bg).place(x=1, y=1, relwidth=1, relheight=1)
        self.frame1()

    # Close Frame One
    def destfr1(self):
        self.frame1.destroy()

    # Starting Frame
    def frame1(self):
        self.frame1 = Frame(self.root, bg="white")
        self.frame1.place(x=300, y=450, width=1100, height=100)
        title = Label(self.frame1, text="Please insert network address for device scan: ", font=("Arial", 20, "bold"),
                      bg="white").place(x=50, y=30)
        self.var_ipentry = StringVar()
        ipentry = Entry(self.frame1, font=("Arial", 20, "bold"), bg="white", fg="red",
                        textvariable=self.var_ipentry).place(x=680, y=30)
        self.btn_img = ImageTk.PhotoImage(file="images/magnifying-glass.png")
        btn = Button(self.frame1, image=self.btn_img, bg="blue", cursor="hand2", command=self.provide_address).place(
            x=1010, y=25)

    # Second Frame
    def frame2(self, des_list):
        self.frame1 = Frame(self.root, bg="white")
        self.frame1.place(x=250, y=250, width=1100, height=600)
        # Using treeview widget
        treev = ttk.Treeview(root, selectmode='browse')

        # Calling pack method w.r.to treeview
        treev.place(x=250, y=250, width=1100, height=600)

        # Constructing vertical scrollbar
        # with treeview
        verscrlbar = ttk.Scrollbar(root, orient="vertical", command=treev.yview)

        # Calling pack method w.r.to verical
        # scrollbar
        verscrlbar.place(x=235, y=235)

        # Configuring treeview
        treev.configure(xscrollcommand=verscrlbar.set)

        # Defining number of columns
        treev["columns"] = ("1", "2", "3")
        # Defining heading
        treev['show'] = 'headings'

        # Assigning the width and anchor to  the
        # respective columns
        treev.column("1", width=90, anchor='c')
        treev.column("2", width=90, anchor='se')
        treev.column("3", width=90, anchor='se')

        # Assigning the heading names to the
        # respective columns
        treev.heading("1", text="CPE")
        treev.heading("2", text="CVE")
        treev.heading("3", text="DESCRIPTION")

        # Inserting the items and their features to the
        # columns built
        treev.insert("", 'end', text="L1",
                     values=("Nidhi", "F", "25"))
        for item in des_list:
            for index in range(len(item.cve_col)):
                treev.insert("", 'end', text='L1', values=(item.cpe_name, item.cve_col[index], item.desc_col[index]))

        # Close app



    def close_window(self):
        root.destroy()

    # Provide ip address to procedure
    def provide_address(self):
        if self.var_ipentry.get() == "":
            messagebox.showerror("Error! Provide Value", "NETWORK ADDRESS CANNOT BE BLANK", parent=self.root)
        else:
            threading.Thread(target=Procedures.procedure(self.var_ipentry.get())).start()


class Procedures:

    def procedure(ipaddress):
        asf = UI(root)
        ipaddrs = ipaddress
        np = NmapParse()
        values = np.NmapScanParse(ipaddrs)
        val = '0'

        # CPE_LIST einai h lista pou 8a steileis telika gia na kaneis populate to treeview
        # periexei antikeimena typou CPE

        # CPE einai antikeimeno me onoma tou cpe, lista cve, lista description
        cpe_list = []

        for i in values:
            cpevl = (i)
            cpevl2 = str(cpevl).replace('[', '(').replace(']', ',)')
            cpevl3 = cpevl2.replace('(\'', '').replace('\',)', '').replace(" ", '')
            query = "SELECT cpe FROM cpetbl WHERE cpe LIKE '{}'".format(cpevl3)
            mycursor.execute(query, cpevl2)
            myresult = mycursor.fetchall()

            if len(myresult) == 0: #CHECK : Not in table
                # print("Device CPE " + cpevl2 + "  NOT IN table")
                result = tkinter.messagebox.askquestion('CPE NOT IN DATABASE', 'IS  %s  RELATED TO AN IOT DEVICE?' %(str(cpevl3)))
                if result == 'yes':
                    cve, description = np.ParseNVDJson(cpevl3)
                    cpe_obj = CPE(cpevl3, cve, description)  # Creation of object
                    cpe_list.append(cpe_obj)  # Insertion to list
                    mycursor.execute("INSERT IGNORE INTO cpetbl (cpe,iot) VALUES (%s,'YES')", cpevl)
                    mydb.commit()
                else:
                    mycursor.execute("INSERT IGNORE INTO cpetbl (cpe,iot) VALUES (%s,'NO')", cpevl)
                    mydb.commit()
                    #root.destroy()  # Closing Tkinter window forcefully.

                print(mycursor.rowcount, "record were inserted.")


                # print(cve, description)
            else: #CHECK: CPE IS IN TABLE
                query2 = "SELECT cpe FROM cpetbl WHERE cpe LIKE '{}' AND iot = 'YES'".format(cpevl3)
                mycursor.execute(query2, cpevl2)
                myresult2 = mycursor.fetchall()
                #print("SPERAAAAAAAAAAAAAA",str(myresult2).replace('[', '').replace('(\'', '').replace('\',)]', ''))
                if len(myresult2) == 0: #IT IS IN TABLE and is NOT iot
                    print("Device CPE " + cpevl2 + " already exists in table and IS NOT iot")

                else: #IT IS IN TABLE AND IS IOT
                    #print("Device CPE " + cpevl2 + " already exists in table and IS  iot")
                    cve, description = np.ParseNVDJson(cpevl3)
                    cpe_obj = CPE(cpevl3, cve, description)  # Creation of object
                    cpe_list.append(cpe_obj)  # Insertion to list

        #for ind in cpe_list:
            #print(ind.cpe_name)
            #print(ind.cve_col)
            #print(ind.desc_col)

        asf.destfr1()
        asf.frame2(cpe_list)



mydb.commit()
root = Tk()
obj = UI(root)
root.mainloop()
