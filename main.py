import nmap
import json
import mysql.connector
from JsonParsing import NmapParse
from tkinter import *
from GUI import App

from cpe import CPE
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="root",
    database="cpeiotdb"
)






mycursor = mydb.cursor()

#mycursor.execute("DELETE from cpetbl")

#print(mydb)

ipaddrs = "192.168.66.10/28"
np = NmapParse()
values = np.NmapScanParse(ipaddrs)
val = '0'


for i in values:
        cpevl = (i)
        cpevl2 = str(cpevl).replace('[', '(').replace(']', ',)')
        cpevl3 = cpevl2.replace('(\'', '').replace('\',)', '').replace(" ", '' )
        query = "SELECT cpe FROM cpetbl WHERE cpe LIKE '{}'".format(cpevl3)
        mycursor.execute(query, cpevl2)
        myresult = mycursor.fetchall()
        if len(myresult) == 0:
            print("Device CPE " + cpevl2 + "  NOT IN table")
            cve, description = np.ParseNVDJson(cpevl3)
            print (cve, description)
        else:
            query2 = "SELECT cpe FROM cpetbl WHERE cpe LIKE '{}' AND iot = 'YES'".format(cpevl3)
            mycursor.execute(query2, cpevl2)
            myresult2 = mycursor.fetchall()
            if len(myresult2) == 0:
                print("Device CPE " + cpevl2 + " already exists in table and IS NOT iot")
                np.ParseNVDJson(cpevl3)
                #c11 = CPE((cpevl3), CPE.VERSION_2_2)
                #c22 = c11.as_wfn()
               # print("CHECK HERE MAN :",c22)
            else:
                print("Device CPE " + cpevl2 + " already exists in table and IS iot")








#val = mycursor.executemany("SELECT * FROM cpetbl WHERE (cpe) like (%s)", values)


#mycursor.executemany("INSERT IGNORE INTO cpetbl (cpe) VALUES (%s)", values)
#mycursor.execute("SELECT * FROM cpetbl")
#myresult = mycursor.fetchall()

#for x in myresult:
 # print(x)


#print (values)
#print(mycursor.rowcount, "record were inserted.")
#mycursor.execute("CREATE TABLE cpetbl (id INT AUTO_INCREMENT PRIMARY KEY, cpe VARCHAR(255) UNIQUE, iot VARCHAR(255))")
mydb.commit()
