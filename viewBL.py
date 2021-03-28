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

def runViewBL():
    bl = open("bl.txt","r")
    print("\nViewing blacklist\n")
    print(bl.read())
    bl.close()
    con = input("Press any key to continue")
