import threading
from tkinter import *
from tkinter import messagebox
from PIL import Image,ImageTk
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

class Procedures:
        def procedure(ipaddress):
                ipaddrs = ipaddress
                np = NmapParse()
                values = np.NmapScanParse(ipaddrs)
                val = '0'

                for i in values:
                        cpevl = (i)
                        cpevl2 = str(cpevl).replace('[', '(').replace(']', ',)')
                        cpevl3 = cpevl2.replace('(\'', '').replace('\',)', '').replace(" ", '')
                        query = "SELECT cpe FROM cpetbl WHERE cpe LIKE '{}'".format(cpevl3)
                        mycursor.execute(query, cpevl2)
                        myresult = mycursor.fetchall()
                        if len(myresult) == 0:
                                print("Device CPE " + cpevl2 + "  NOT IN table")
                                cve, description = np.ParseNVDJson(cpevl3)
                                print(cve, description)
                        else:
                                query2 = "SELECT cpe FROM cpetbl WHERE cpe LIKE '{}' AND iot = 'YES'".format(cpevl3)
                                mycursor.execute(query2, cpevl2)
                                myresult2 = mycursor.fetchall()
                                if len(myresult2) == 0:
                                        print("Device CPE " + cpevl2 + " already exists in table and IS NOT iot")
                                        np.ParseNVDJson(cpevl3)
                                        # c11 = CPE((cpevl3), CPE.VERSION_2_2)
                                        # c22 = c11.as_wfn()
                                        # print("CHECK HERE MAN :",c22)
                                else:
                                        print("Device CPE " + cpevl2 + " already exists in table and IS iot")
                UI.close_window(root)
class UI:

        def __init__(self,root):
                self.root=root
                self.root.title("IOT VULNERABILITY SYSTEM")
                self.root.geometry("1600x900+0+0")
                self.root.config(bg="white")



        # Background
                self.bg=ImageTk.PhotoImage(file="images/main.png")
                bg= Label(self.root,image=self.bg).place(x=1,y=1,relwidth=1,relheight=1)


        #Main frame
                frame1=Frame(self.root,bg="white")
                frame1.place(x=300,y=450,width=1100,height=100)

                title=Label(frame1,text="Please insert network address for device scan: ", font=("Arial",20,"bold"),bg="white").place(x=50,y=30)

                self.var_ipentry=StringVar()
                ipentry=Entry(frame1,font=("Arial",20,"bold"),bg="white", fg="red",textvariable=self.var_ipentry).place(x=680,y=30)
                self.btn_img=ImageTk.PhotoImage(file="images/magnifying-glass.png")
                btn=Button(frame1,image=self.btn_img,bg="blue",cursor="hand2",command=self.provide_address).place(x=1010, y=25)

        def close_window(self):
                root.destroy()

        def provide_address(self):
                if self.var_ipentry.get()=="":
                        messagebox.showerror("Error! Provide Value","NETWORK ADDRESS CANNOT BE BLANK",parent=self.root)
                else:
                        threading.Thread(target = Procedures.procedure(self.var_ipentry.get())).start()








root=Tk()
obj=UI(root)
root.mainloop()