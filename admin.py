import pyshark
from prettytable import PrettyTable
import pyfiglet
from editBL import *
from viewBL import *
from viewAdmin import *
from editAdmin import *
from viewRec import *
from editRec import *

# pip3 install PrettyTable
# pip3 install pyshark

# list of dictionaries used to catalog
# the list of unique IP's and their corresponding ports
# they tried to access as well as overall bytes sent from that IP

# TO DO
# records edit/viewing
# admins add/remove/view
# make record txt


# colors used for initial Table Formatting
R = "\033[0;31;40m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;34;40m"
N = "\033[0m"  # put after each color set
C = "\033[1;96m"


def runAdmin():
    start = True
    while (start):
        # user input for usernames and passwords
        user = input("Username: ")
        pwd = input("Password: ")

        # sets admin access as false
        admin = False

        numAttempts = 1

        with open("admin.txt", "r") as usr:
            combos = usr.readlines()
        for i in range(len(combos)):
            combos[i] = combos[i].strip("\n")

        while numAttempts < 3:

            # print(combos[0])
            for i in range(len(combos)):

                if combos[i] == str(user):
                    if combos[i + 1] == str(pwd):
                        admin = True
                        break

            if not admin:
                print("Wrong username or password. You have " + str(3 - numAttempts) + " attempts left.")
                user = input("Username: ")
                pwd = input("Password: ")
                numAttempts += 1

                if numAttempts == 3:
                    print(R + "Authentication failed, back to start page." + N)
                    return
            else:
                break
        admin = True

        # options menu
        print("Welcome " + C + user + N + ". What can we help you with?\n")
        print(Y + "1" + N + ": Edit blacklisted IPs")
        print(Y + "2" + N + ": View Blacklisted IPs")
        print(Y + "3" + N + ": Edit Threat records")
        print(Y + "4" + N + ": View threat records")
        print(Y + "5" + N + ": Edit Administrator list")
        print(Y + "6" + N + ": View Administrator list")
        print(Y + "7" + N + ": Exit Administration mode and go to testing")

        while admin:
            choice = input("Edit IP list" + Y + " 1" + N + ", " +
                           "View IP list" + Y + " 2" + N + ", " +
                           "Edit Records" + Y + " 3" + N + ", " +
                           "View Records" + Y + " 4" + N + ", " +
                           "Edit Admin" + Y + " 5" + N + ", " +
                           "View Admin" + Y + " 6" + N + ", " +
                           "Exit" + Y + " 7" + N + ": ")
            ######################### editing ##############################
            if choice == "1":  # 3
                runEditBL()
            ######################### viewing ##############################
            elif choice == "2":  # 3
                runViewBL()
            ######################### edit records #########################
            elif choice == "3":  # 3
                runEditRecords(2, None)
            ######################### edit records #########################
            elif choice == "4":  # 3
                runViewRecords()
            ######################### edit records #########################
            elif choice == "5":  # 3
                runEditAdmin()
            ######################### edit records #########################
            elif choice == "6":  # 3
                runViewAdmin()
            ######################### exiting ##############################
            elif choice == "7":
                chk = input("Are you sure you want to leave" +
                            " (" + Y + "y" + N + " or " + Y + "n" + N + ")? ")
                if chk == "y":
                    admin = False
                    return
                else:
                    admin = True
            else:
                print("Bad input. Try again.")
