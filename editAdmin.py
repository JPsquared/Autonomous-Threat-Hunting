import pyshark
from prettytable import PrettyTable
import pyfiglet
from viewAdmin import *

# pip3 install PrettyTable
# pip3 install pyshark


# 4 more modules to branch off from this file


# list of dictionaries used to catalog
# the list of unique IP's and their corresponding ports
# they tried to access as well as overall bytes sent from that IP
ipData = []

# colors used for initial Table Formatting
R = "\033[0;91m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;94m"
N = "\033[0m"  # put after each color set


def runEditAdmin():
    runViewAdmin()
    ec = input("Editing, add " + Y + "(1)" + N + " or remove " + Y + "(2)" + N + ": ")
    # ################### adding ip ############################
    if ec == "1":
        ad = open("admin.txt", "r+")
        x = ad.read()
        print(x)
        if x != "":
            ad.write("\n")

        adduser = input("Username to add: ")
        addpwd = input("Password for this user: ")
        if adduser == addpwd:
            print("Can't have matching username and password")
            ad.close()
            return
        ad.write(adduser)
        ad.write("\n")
        ad.write(addpwd)
        ad.write("\n")
        ad.close()
        print("Added the user " + adduser + "!")
        # ####################### removing ip #################
    elif ec == "2":
        remuser = input("Remove which user: ")
        with open("admin.txt", "r") as ad:
            combos = ad.readlines()
            with open("admin.txt", "w") as ad:
                for i in range(len(combos)):
                    combos[i] = combos[i].strip("\n")
                print(combos)
                order = 0
                while order in range(len(combos) - 1):
                    if combos[order] == remuser:
                        del combos[order]
                        del combos[order]
                        if order != len(combos):
                            del combos[order]
                    order += 1
                    if len(combos) == 0:
                        # ad.write("\n")
                        return
                    elif combos[len(combos) - 1] == "":
                        del combos[len(combos) - 1]

                print(combos)

                for i in range(len(combos)):
                    if combos[i] == "":
                        ad.write("\n")
                    else:
                        ad.write(combos[i])
                        ad.write("\n")
