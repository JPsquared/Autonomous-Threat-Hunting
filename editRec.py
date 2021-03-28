# edit Record file

import pyshark
from prettytable import PrettyTable
import pyfiglet
import datetime
from viewRec import *

# pip3 install PrettyTable
# pip3 install pyshark


# FORMAT FOR THE RECORD Table, all one line in txt file

# RECORD NUMBER | TIME OF RECORD | PCAP FILE NAME | MODULE 1 % | ... x % |
#               | PROBABILITY OF THREAT


# colors used for initial Table Formatting
R = "\033[0;91m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;94m"
N = "\033[0m"  # put after each color set


def runEditRecords(ec, recToAdd):
    # rec = open("rec.txt", "r+")
    # print(rec.read())
    # rec.close()
    count = 0
    with open("rec.txt", "r") as rec:
        lines = rec.readlines()
        for line in lines:
            count += 1

    # give option to manually remove, but not add
    # c= input("Editing, add "+Y+"(1)"+N+" or remove "+Y+"(2)"+N+": ")
    #################### adding ip ############################
    if ec == 1 and recToAdd is not None:

        curtime = str(datetime.datetime.now())

        # addRec = input("Record to add (Format \"123.45.678.910\"): ")
        formatted = str(count + 1) + " | " + curtime + " | " + str(recToAdd)
        rec = open("rec.txt", "r+")
        rec.read()
        rec.write(formatted)
        rec.write("\n")
        rec.close()
        print("Added record to rec.txt!")
        ######################## removing ip #################
    elif ec == 2 and recToAdd is None:
        runViewRecords()
        if count == 0:
            print("Nothing to remove")
            return
        remrec = input("remove which record? (Choose a number 1 - " + str(count) + "): ")  # get length)
        try:
            if int(remrec) > count:
                print("Out of bounds, going back to options")
                return
        except ValueError:
            print("Bad input, going back to options")
            return
        with open("rec.txt", "r") as rec:
            lines = rec.readlines()
            x = 1
            with open("rec.txt", "w") as rec:
                for line in lines:
                    row = line.split(" | ")
                    num = row[0]
                    if num != str(remrec):
                        row[0] = str(x)
                        newline = " | ".join(row)
                        rec.write(newline)
                        x += 1
        print("Removed record " + str(remrec))
