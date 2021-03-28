# 13.3 looking for port access attempts from a distinct source IP

import pyshark
from prettytable import PrettyTable
import pyfiglet
from learning import *
import ipaddress


def ipAccAtt():
    print("Welcome to the Source IP Access Attempts Module!")
    prtAttempts = dict()

    evaluate = True
    while (evaluate):

        print("\nq to exit")
        fileTouse = input("Input a .pcap file for us to evalutate: ")

        try:
            if(fileTouse == "live"):
                capture = pyshark.LiveCapture(interface='enp0s3', bpf_filter='udp port 53')
                capture.sniff(packet_count=50)
            else:
                capture = pyshark.FileCapture(fileTouse)
                print("Got it!")
        except FileNotFoundError:
            if fileTouse == "q":
                return
            print(R+"That file is not found, or was input incorrectly."+N)
            continue

        print("Working on "+ fileTouse+"...")

        pcapSum = PrettyTable(["Source IP", "Average Number of Destination IP's"])
        firstTS = float(0)
        PAtotals = {}
        for packet in capture:
            try:
                #get source, get dest, get port, if all distinct add to list
                sa= packet.ip.src
                da = packet.ip.dst
                
                if sa in PAtotals:
                    if da not in PAtotals[sa]:
                        PAtotals[sa].append(da)
                else:
                    PAtotals[sa] = []

            except AttributeError as e:
                pass
        for x in PAtotals.keys():
            pcapSum.add_row([str(x), str(len(PAtotals[x]))])
        print(pcapSum)
        
        learner = Learner()
        train_learner(learner)
        test_learner(learner)
    return



def train_learner(learner):
    X_vals = []
    Y_vals = [] 
    evaluate = True
    while (evaluate):
        fileTouse = "benign_train2.pcap"
        try:
            if(fileTouse == "live"):
                capture = pyshark.LiveCapture(interface='enp0s3', bpf_filter='udp port 53')
                capture.sniff(packet_count=50)
            else:
                capture = pyshark.FileCapture(fileTouse)
        except FileNotFoundError:
            if fileTouse == "q":
                return
            print(R+"That file is not found, or was input incorrectly."+N)
            continue

        
        firstTS = float(0)
        PAtotals = {}
        i = 0
        for packet in capture:
            i += 1
            try:
                #get source, get dest, get port, if all distinct add to list
                sa= packet.ip.src
                da = packet.ip.dst
                
                if sa in PAtotals:
                    if da not in PAtotals[sa]:
                        PAtotals[sa].append(da)
                else:
                    PAtotals[sa] = []

            except AttributeError as e:
                pass
            if i > 5000:
                break
        for x in PAtotals.keys():
            X_vals.append([int(ipaddress.ip_address(str(x))), int(len(PAtotals[x]))])
            Y_vals.append('benign')
        break

        
    evaluate = True
    while (evaluate):
        fileTouse = "malicious_train.pcap"
        try:
            if(fileTouse == "live"):
                capture = pyshark.LiveCapture(interface='enp0s3', bpf_filter='udp port 53')
                capture.sniff(packet_count=50)
            else:
                capture = pyshark.FileCapture(fileTouse)
        except FileNotFoundError:
            if fileTouse == "q":
                return
            print(R+"That file is not found, or was input incorrectly."+N)
            continue

        print('here')
        firstTS = float(0)
        PAtotals = {}
        i = 0
        for packet in capture:
            i += 1
            try:
                #get source, get dest, get port, if all distinct add to list
                sa= packet.ip.src
                da = packet.ip.dst
                
                if sa in PAtotals:
                    if da not in PAtotals[sa]:
                        PAtotals[sa].append(da)
                else:
                    PAtotals[sa] = []

            except AttributeError as e:
                pass

            if i > 5000:
                break
        for x in PAtotals.keys():
            X_vals.append([int(ipaddress.ip_address(str(x))), int(len(PAtotals[x]))])
            Y_vals.append('malicious')
        

        
        break


    
    learner.train(X_vals, Y_vals)

def test_learner(learner):
    X_vals = []
    Y_vals = []
    evaluate = True
    while (evaluate):
        fileTouse = "testing.pcap"
        try:
            if(fileTouse == "live"):
                capture = pyshark.LiveCapture(interface='enp0s3', bpf_filter='udp port 53')
                capture.sniff(packet_count=50)
            else:
                capture = pyshark.FileCapture(fileTouse)
        except FileNotFoundError:
            if fileTouse == "q":
                return
            print(R+"That file is not found, or was input incorrectly."+N)
            continue

        
        firstTS = float(0)
        PAtotals = {}
        i = 0
        for packet in capture:
            i += 1
            try:
                #get source, get dest, get port, if all distinct add to list
                sa= packet.ip.src
                da = packet.ip.dst
                
                if sa in PAtotals:
                    if da not in PAtotals[sa]:
                        PAtotals[sa].append(da)
                else:
                    PAtotals[sa] = []

            except AttributeError as e:
                pass

            if i > 5000:
                break

        for x in PAtotals.keys():
            X_vals.append([int(ipaddress.ip_address(str(x))), int(len(PAtotals[x]))])
            Y_vals.append('benign')
        break


    
    
    learner.test(X_vals, Y_vals)


