# Autonomous-Threat-Hunting

The goal of this software is to detect threats within captured pcap files. The software can be loaded onto a host to 
perform these functions on medium to small sized pcap files for analysis. An administrator can view the records of 
tests, recognize blacklisted IP’s that have previously been identified, and edit records, targeted IP’s, as well as 
modify administrator access.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing 
purposes.

### Prerequisites

Following is a list of prerequisite libraries employed in the project:

* `sklearn`
* `numpy`
* `pyshark`
* `prettytable`
* `pyfiglet`

To install these libraries onto your machine, we recommend using pip3. For example, the command:

```
pip3 install sklearn
```

Will install the sklearn library to your machine. No further action is required to complete installation.

### Installing

A step by step series of examples that tell you how to get a copy of the project running on your machine.

#### Get Code

Obtain a copy of all code contained here either by cloning this repository to your machine or by downloading a 
compressed folder containing all project files and placing it where you would like the code to run.

To clone the repository, run: `git clone https://github.com/JPsquared/Autonomous-Threat-Hunting.git`

#### Run the Program

To run the program, execute the following line of code in a terminal:

```python3 ath.py```

Introductory information will be displayed, then the screen will then give you choices for 1, testing, or 2, system 
admin. Option 3 will exit the program.

After selecting 1, you will be presented to choose a module to examine and test a pcap on. Follow number choices in 
order to determine how you want to test.

You can also choose system admin. You will need to input a username and password.

* INITIAL USERNAME: USNA
* INITIAL PASSWORD: 2021

Once access has been gained, you can view/edit, records, admins, and the IP blacklist.

## Authors

* **Sean Bowman** - Group Leader
* **Matt Ransom**
* **Ethan Dupre**
* **Brody Jenkins**
* **John Paul Post**

## File Descriptions

### System Admin Files

* `viewRec.py `- allows user to records of tests
* `editRec.py` - editing records
* `viewAdmin.py` - viewing admin passwords and usernames
* `editAdmin.py` - editing admin access
* `viewBL.py` - viewing blacklisted IPs
* `editBL.py` - editing blacklisted IPs

### Testing Files

* `timing.py` - used for determining interpacket spacing of packets
* `IPAA.py`- feature extraction for port access attempts
* `testing.py` - used for selection of features, and general analytics

### Learning Files

* `learning.py` - used to create a classifier model that will determine threatening behavior
