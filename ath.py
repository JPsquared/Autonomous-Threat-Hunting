import pyshark
from prettytable import PrettyTable
import pyfiglet

from testing import *
from admin import *

#pip3 install PrettyTable
#pip3 install pyshark
#pip3 install pyfiglet

#list of dictionaries used to catalog
#the list of unique IP's and their corresponding ports
#they tried to access as well as overall bytes sent from that IP


#colors used for initial Table Formating
BR = "\033[1;91m"
R = "\033[0;91m"
G = "\033[1;32m"
Y = "\033[93m"
B = "\033[0;34;40m"
N = "\033[0m"
C = "\033[1;96m"
YB = "\033[1;33m"
 #put after each color set

intro = pyfiglet.figlet_format("ATH", font = "slant" )
print("\n" + BR + intro + N +"\n")
print("Welcome to Autonomous Threat Hunting! \nCreated by")
print("\tEthan Dupre (" + C + "The Rogue" + N + ")" )
print("\tBrody Jenkins (" + BR + "The Barbarian " + N + ")" )
print("\tSean Bowman (" + YB + "The Bard" + N +") \n\t"+
"Matt Ransom (" + G + "The Ranger" + N +")\n")
start = True
while(start):
    setting = input("Enter "+Y+"1"+N+" for testing, "+Y+"2"+N+
    " for System Administration, " +Y+"3"+N+" to exit program: ")

    if setting == "1":
        # add testing module here\
        runTest()
        #print( R + "GO TO TESTING MODULE" + N)

    elif setting == "2":
        runAdmin()
        # add admin module here
        #print(R + "GO TO ADMIN MODULE" + N )

    elif setting == "3":
        chk = input("Are you sure you want to leave"+
        " ("+Y+"y"+N+" or "+Y+"n"+N+")? ")
        if chk == "y":
            print(Y + "Goodbye, have a super excellent day" + N)
            exit()
        elif chk == "n":
            print(Y + "Okay, back to the beginnning then." + N)
        else:
            print(Y + "Please input a valid option" + N)
    else:
        print(Y + "Please cooperate with the system and input a valid number" + N)
