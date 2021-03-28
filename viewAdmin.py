import pyshark
from prettytable import PrettyTable
import pyfiglet

# pip3 install PrettyTable
# pip3 install pyshark

# colors used for initial Table Formatting
R = "\033[0;91m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;94m"
N = "\033[0m"  # put after each color set


def runViewAdmin():
    ad = open("admin.txt", "r")
    print("\nViewing Usernames and Passwords\n")
    print("Format\n<Username>\n<Password>\n")
    print(ad.read())
    ad.close()
