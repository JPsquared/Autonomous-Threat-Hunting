# view record file

import pyshark
from prettytable import PrettyTable
import pyfiglet
import datetime

#pip3 install PrettyTable
#pip3 install pyshark







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

#makes a table of the records, which you can view by certain categories and
#and view based off module #, by alphabetical of pcap name, timestamp, etc.

def runViewRecords():

    current_time = datetime.datetime.now()

    recordSum = PrettyTable(["Record #","Timestamp","File name","Module 1 %",
    "Module 2 %","Module 3 %", "Module 4 %","Probability of threat"])

    with open("rec.txt","r") as rec:
        lines = rec.readlines()
        for line in lines:
            if line is not "\n":
                row = line.split(" | ")
                recordSum.add_row([row[0],row[1],row[2],row[3],
                row[4],row[5],row[6],row[7].strip("\n")])

    #recordSum.add_row([packetsTotal, source_address , destination_address ,
    #source_port , destination_port , urlSrc, protocol, length, G+"PASS"+N])

    print("\nTime is "+ str(current_time))
    #rec = open("rec.txt","r")
    print("\nViewing records...\n")
    print(recordSum)
    #rec.close()
    #con = input("Press any key to continue")
