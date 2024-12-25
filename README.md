Intrusion Detection and Prevention System (IDPS)

Overview

This Python-based Intrusion Detection and Prevention System (IDPS) uses the Scapy library to monitor network traffic for suspicious patterns or activities. The system inspects packets in real time and identifies potential threats, such as packets originating from blacklisted IP addresses or packets with uncommon TCP flags, like SYN+FIN.

Features

Real-Time Packet Analysis: Captures and inspects network traffic using the Scapy library.

IP Blacklist Detection: Detects packets from pre-defined suspicious IP addresses.

TCP Flag Analysis: Flags unusual combinations like SYN+FIN, which may indicate malicious behavior.

Extensible Design: Easily adaptable to include more detection rules or integrate with other monitoring tools.

Prerequisites

To use this script in Google Colab or locally:

Python 3.x installed on your machine.

Scapy library installed. You can install it using:

pip install scapy

Usage Instructions

Setup:

Add suspicious IPs to the SUSPICIOUS_IPS list in the script.

Run the Script:

In a Python environment or Google Colab, execute the script.

The program will begin sniffing packets and print alerts for suspicious activity.

Alerts:

Alerts are displayed in the console to detect suspicious IP addresses or unusual TCP flags.

Limitations

It does not include active IP blocking since it is designed for environments like Google Colab, which lacks administrative privileges.

Limited to real-time detection without historical traffic analysis.

Future Enhancements

Integration with Firewall Tools: Automate blocking of suspicious IPs.

Logging: Add functionality to store alerts in a log file for further analysis.

Advanced Analysis: Implement payload inspection or machine learning-based anomaly detection.
