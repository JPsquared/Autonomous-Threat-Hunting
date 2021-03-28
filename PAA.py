# 13.3 looking for port access attempts from a distinct source IP

import pyshark
from prettytable import PrettyTable
import pyfiglet


def prtAccAtt():
    print("Welcome to the Port Access Attempts Module!")
    prtAttempts = dict()  # not used

    evaluate = True
    while evaluate:

        print("\nq to exit")
        fileTouse = input("Input a .pcap file for us to evaluate: ")

        try:
            if fileTouse == "live":
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

        pcapSum = PrettyTable(["Source IP", "Distinct Port Access Attempts"])
        firstTS = float(0)  # not used
        PAtotals = {}
        for packet in capture:
            try:
                # get source, get dest, get port, if all distinct add to list
                sa = packet.ip.src
                da = packet.ip.dst
                dp = packet[packet.transport_layer].dstport

                PAlist = []
                PAAcurrent = (sa, da, dp)
                if PAAcurrent not in PAlist:
                    PAlist.append(PAAcurrent)
                    if sa in PAtotals.keys():
                        PAtotals[sa] = PAtotals[sa] + 1
                    else:
                        PAtotals[sa] = 1
                else:
                    continue

            except AttributeError as e:
                pass

        for x in PAtotals.keys():
            pcapSum.add_row([str(x), str(PAtotals[x])])
        print(pcapSum)
    return
