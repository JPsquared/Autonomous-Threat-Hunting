import pyshark
from prettytable import PrettyTable
import pyfiglet


def IPS():
    print("Welcome to the interpacket spacing module!")
    pktTiming = dict()

    evaluate = True
    while evaluate:

        print("\nq to exit")
        fileTouse = input("Input a .pcap file for us to evaluate: ")

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

        pcapSum = PrettyTable(["Source IP", "Average Interpacket Spacing"])
        firstTS = float(0)
        for packet in capture:
            try:
                stamp = str(packet.sniff_time).split(" ")[1].split(":")
                hTs = float(stamp[0]) * 3600
                mTs = float(stamp[1]) * 60
                s = float(stamp[2])
                absTime = hTs + mTs + s

                if firstTS == 0:
                    firstTS = absTime
                else:
                    absTime = absTime - firstTS

                src = packet.ip.src

                if src not in pktTiming:
                    # tLastPkt, time between, numPkts
                    if absTime > 1000:
                        pktTiming[src] = [0, 0, 1]
                    else:
                        pktTiming[src] = [absTime, 0, 1]

                else:
                    pktTiming[src][1] += absTime - pktTiming[src][0]
                    pktTiming[src][0] = absTime
                    pktTiming[src][2] += 1

            except AttributeError:
                pass

        for x in pktTiming.keys():
            try:
                pcapSum.add_row([str(x), str(float(pktTiming[x][1] / (pktTiming[x][2] - 1)))])
            except ZeroDivisionError as e:
                pcapSum.add_row([str(x), "Single Packet!"])

        print(pcapSum)

    return
