# Autonomous-Threat-Hunting

USNA Capstone 2021

### To Run:

```python3 ath.py```
The screen will then give you choices for 1, testing, or 2, system admin.
Option 3 will exit the program.

After selecting 1, you will be presented to choose a module to examine and test a pcap on. Follow number 
choices in order to determine how you want to test.

You can also choose system admin. You will need to input a username and
password.

INITIAL USERNAME: USNA
INITIAL PASSWORD: 2021

Once access has been gained, you can view/edit, records, admins, and the
IP blacklist.

System Admin Files:
viewRec.py - allows user to records of tests
editRec.py - editing records
viewAdmin.py - viewing admin passwords and usernames
editAdmin.py - editing admin access
viewBL.py - viewing blacklisted IPs
editBL.py - editing blacklisted IPs

Testing Files:
timing.py - used for determining interpacket spacing of packets
IPAA.py - feature extraction for port access attempts
testing.py - used for selection of features, and general analytics

Learning Files:
learning.py - used to create a classifier model that will determine threatening
              behavior


Outside library dependencies:
```
prettytable
pyshark
pyfiglet
sklearn
numpy
```
