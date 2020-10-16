from tkinter import *
from tkinter import messagebox
from main import TEST
from PIL import Image,ImageTk





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

        def provide_address(self):
                if self.var_ipentry.get()=="":
                        messagebox.showerror()("Error Provide Value",parent=self.root)
                else:
                        TEST.procedure(self.var_ipentry.get())




root=Tk()
obj=UI(root)
root.mainloop()