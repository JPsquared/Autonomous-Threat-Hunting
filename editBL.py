import pyshark
from prettytable import PrettyTable
import pyfiglet

#pip3 install PrettyTable
#pip3 install pyshark




# 4 more modules to branch off from this file


#list of dictionaries used to catalog
#the list of unique IP's and their corresponding ports
#they tried to access as well as overall bytes sent from that IP
ipData = []

#colors used for initial Table Formating
R = "\033[0;91m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;94m"
N = "\033[0m" #put after each color set

def runEditBL():
    bl = open("bl.txt", "r+")
    print(bl.read())
    ec= input("Editing, add "+Y+"(1)"+N+" or remove "+Y+"(2)"+N+": ")
    #################### adding ip ############################
    if ec == "1":
        addip = input("IP to add (Format \"123.45.678.910\"): ")

        bl.write(addip)
        bl.write("\n")
        bl.close()
        print("Added "+addip+"!")
        ######################## removing ip #################
    elif ec == "2":
        remip = input("remove which IP? (Format \"123.45.678.910\"): ")
        with open("bl.txt","r") as bl:
            lines = bl.readlines()
            with open("bl.txt","w") as bl:
                for line in lines:
                    if line.strip("\n") != remip:
                        bl.write(line)
                        print("Removed "+remip+"!")
                    else:
                        print("Bad input")
