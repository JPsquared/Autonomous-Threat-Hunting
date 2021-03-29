import pyshark
from prettytable import PrettyTable
import pyfiglet
from editRec import *
from learning import Learner
from PAA import *
from timing import *
from IPAA import *


# pip3 install PrettyTable
# pip3 install pyshark


class Record:
    def __init__(self, name, mod1, mod2, mod3, mod4, probability):
        self.module1 = str(mod1)
        self.module2 = str(mod2)
        self.module3 = str(mod3)
        self.module4 = str(mod4)
        self.probability = str(probability)
        self.name = str(name)

    def __str__(self):
        return self.name + " | " \
               + self.module1 + " | " \
               + self.module2 + " | " \
               + self.module3 + " | " \
               + self.module4 + " | " \
               + self.probability


# 4 more modules to branch off from this file


# list of dictionaries used to catalog
# the list of unique IP's and their corresponding ports
# they tried to access as well as overall bytes sent from that IP

# 4 more modules to branch off from this file


# colors used for initial Table Formatting
R = "\033[0;91m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;94m"
N = "\033[0m"  # put after each color set


def runTest():
    print("Are there any particular features you want to analyze?")
    print(Y + "1" + N + ": Standard deviation of interpacketspacing")
    print(Y + "2" + N + ": Byte volume per port")
    print(Y + "3" + N + ": Port access attempts from origin IP address")
    print(Y + "4" + N + ": Destination IP attempts from origin IP address")
    print(Y + "5" + N + ": General analysis")
    choice = input(Y + "1" + N + "," + Y + " 2" + N + "," + Y + " 3" + N + "," + Y + " 4" + N + ": " + " 5" + N + ": ")

    # standard deviation of interpacketspacing
    if choice == "1":
        IPS()

    # Byte volume per port
    elif choice == "2":
        byteVolPerPort()

    # Port access attempts from origin IP address
    elif choice == "3":
        prtAccAtt()

    elif choice == "4":
        ipAccAtt()

    elif choice == "5":
        generalAnalytics()

    else:
        print(Y + "That was not a valid input . . . I expected more from a human like you." + N)


def generalAnalytics():
    # list of dictionaries used to catalog
    # the list of unique IP's and their corresponding ports
    # they tried to access as well as overall bytes sent from that IP
    ipData = []

    evaluate = True
    while evaluate:
        # here we will allow live captures

        print("\nq to exit")
        fileTouse = input("Input a .pcap file (type 'live' to capture/analyze packets): ")

        try:
            if fileTouse == "live":
                print("hello")
                capture = pyshark.LiveCapture(interface='enp0s3', bpf_filter='udp port 53')
                capture.sniff(packet_count=50)
            else:
                capture = pyshark.FileCapture(fileTouse)
                print("Got it!")

        except FileNotFoundError:
            if fileTouse == "q":
                exit()
            print(R + "That file is not found, or was input incorrectly." + N)
            continue

        print("Working on " + fileTouse + "...")

        # 1st table seen, the overall pcap summary Table
        # currently shows example of how threatening packets could be reported based off
        # of numerical data we deem hostile
        pcapSum = PrettyTable(["Packet #", "Source IP", "Destination IP",
                               "SRC_Port", "DST_Port", "Length", "Threat"])

        # blacklist IP
        blacklist = []
        bl = open("bl.txt", "r")
        for line in bl:
            blacklist.append(line.strip())
        packetsTotal = 1

        # the static capture on 'test.pcap'
        # for loop to iterate through all packets seen
        for packet in capture:
            # used try to account for attribute errors in individual packets
            try:
                packetsTotal += 1
                # parse out details from each packet
                protocol = packet.highest_layer
                source_address = packet.ip.src
                source_port = packet[packet.transport_layer].srcport
                destination_address = packet.ip.dst
                destination_port = packet[packet.transport_layer].dstport
                length = packet.length

                # checks if ipData is empty, adds 1st packet if so
                if not ipData:
                    ipData.append({'IP': source_address,
                                   "portsAccessed": [destination_port],
                                   "Volume": int(length)})
                # ###############################################################################
                # not empty, checking for double IPs, or if we need to add a new one
                else:
                    # iterrate over unique IP data lsit so far
                    for i in range(len(ipData)):

                        # checks if current IP matches any in our current analysis
                        if ipData[i]['IP'] == source_address:
                            # add port Accessed to the already detected IP
                            if ipData[i]['portsAccessed'].count(destination_port) == 0:
                                ipData[i]['portsAccessed'].append(destination_port)

                            # add byte Volume to already detected IP
                            ipData[i]['Volume'] += int(length)
                            # will add number of accesses to each port in next iteration
                            # breaks b/c we have found a match, no need to go further
                            break

                        # else if no matches so far and we are at the end of our unqiue
                        # IP data points
                        elif i == len(ipData) - 1:
                            # add a new IP data point to the ipData
                            ipData.append({'IP': source_address,
                                           "portsAccessed": [destination_port],
                                           "Volume": int(length)})

                # here we add an IP to the blacklist
                # (hardcoded as of now for demo purposes)
                # if packetsTotal == 23:
                #    blacklist.append(packet.ip.src)
                # checks future IPs on blacklist and flags them in summary (RED)
                if packet.ip.src in blacklist:
                    pcapSum.add_row([packetsTotal, R + source_address + N,
                                     R + destination_address + N, R + source_port + N, R + destination_port + N,
                                     R + length + N, R + "THREAT" + N])
                # adds to summary table (GREEN)
                else:
                    pcapSum.add_row([packetsTotal, source_address, destination_address,
                                     source_port, destination_port, length, G + "PASS" + N])

            except AttributeError:
                pass

        # prints summary table w/ THREAT & PASS values (hardcoded)
        print("The following is pcapsum:\n")

        print(pcapSum)
        # creates numerical analysis table to input into ML model, eventually
        # outputting some heuristic for how well we could determine the numerical ipData
        # represents a threat
        ipStats = PrettyTable(["IP", "Ports Accessed", "Byte Volume"])
        # populate table with ipData
        for x in ipData:
            if x['IP'] in blacklist:
                ipStats.add_row([R + x['IP'] + N, R + str(x['portsAccessed']), R + str(x['Volume']) + N])
            else:
                ipStats.add_row([x['IP'], x['portsAccessed'], x['Volume']])
            # prints ipData table, shows input to ML model

        # ######################################################################
        print("The following is ipStats: \n")
        print(ipStats)
        print("\n")
        mod1 = 0
        mod2 = 0
        mod3 = 0
        mod4 = 0
        prob = 0

        recToAdd = Record(fileTouse, mod1, mod2, mod3, mod4, prob)

        runEditRecords(1, recToAdd)
        # #######################################################################
        ck = input("Do you want to run another test (" + Y + "y" + N + ") or (" + Y + "n" + N + ")?")
        if ck == "n":
            evaluate = False
            print(Y + "Going back to main module" + N)


def byteVolPerPort():
    learn = Learner()

    print(Y + "This is the module for Byte Volume By Port" + N)
    portData = []

    evaluate = True
    while evaluate:

        print("\nq to exit")
        fileTouse = input("Input a .pcap file for us to evalutate: ")

        try:
            if fileTouse == "live":
                print("hello")
                capture = pyshark.LiveCapture(interface='enp0s3', bpf_filter='udp port 53')
                capture.sniff(packet_count=50)
            else:
                capture = pyshark.FileCapture(fileTouse)
                print("Got it!")

        except FileNotFoundError:
            if fileTouse == "q":
                return
            print(R + "That file is not found, or was input incorrectly." + N)
            continue

        print("Working on " + fileTouse + "...")

        pcapSum = PrettyTable(["Port", "Byte Volume"])

        for packet in capture:
            try:
                destination_port = packet[packet.transport_layer].dstport
                length = packet.length

                # portData is empty so add the first port
                if not portData:
                    portData.append({'Destination Port': destination_port,
                                     'Byte Volume': int(length)})
                # portData is not empty -> check for ports used more than once
                else:
                    # iterate over already used ports
                    for i in range(len(portData)):
                        if portData[i]["Destination Port"] == destination_port:
                            # add current packet size to port volume
                            portData[i]["Byte Volume"] += int(length)

                            # breaks b/c we have found a match, no need to go further
                            break

                        # else if no matches so far and we are at the end of our unqiue
                        # port data points
                        elif i == len(portData) - 1:
                            # add a new port data point to portData
                            portData.append({"Destination Port": destination_port, "Byte Volume": int(length)})

            except AttributeError:
                pass

        for x in portData:
            pcapSum.add_row([x['Destination Port'], str(x['Byte Volume'])])

        print(pcapSum)

        print('\n\n')

        train_learner(learn)
        test_learner(learn)

        X_vals = []
        for i in portData:
            vals = list(i.values())
            x = [int(vals[0]), vals[1]]
            X_vals.append(x)

        predictions = learn.clf.predict(X_vals)

        correct = 0
        count = 0
        for tag in predictions:
            if tag == 'malicious':
                correct += 1
            count += 1
        percent = (correct / count) * 100
        print("Input file predicted to have", percent, "% of malicious connections. \n")

    return


def train_learner(learner):
    f = open('training-data.txt', 'r')
    X_vals = []
    Y_vals = []
    for line in f:
        line = line.split()
        x = []
        if line[0] == '-':
            x.append(-1)
        else:
            x.append(int(line[0]))
        if line[1] == '-':
            x.append(-1)
        else:
            x.append(int(line[1]))
        X_vals.append(x)
        Y_vals.append(line[2].lower())

    learner.train(X_vals, Y_vals)


def test_learner(learner):
    f = open('testing.txt', 'r')
    X_vals = []
    Y_vals = []
    for line in f:
        line = line.split()
        x = []
        if line[0] == '-':
            x.append(-1)
        else:
            x.append(int(line[0]))
        if line[1] == '-':
            x.append(-1)
        else:
            x.append(int(line[1]))
        X_vals.append(x)
        Y_vals.append(line[2].lower())

    learner.test(X_vals, Y_vals)
