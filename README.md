This repository contains two versions of a network packet sniffer.

Version 1: CodeAlpha_Network_Packet_Sniffer.py

This file contains a real-time network packet sniffer that captures packets and displays their details directly in the terminal. 
The code unpacks Ethernet frames, processes IPv4 packets, and identifies ICMP, TCP, and UDP protocols. 
It provides detailed debugging information and error handling to ensure the integrity of the captured packets. 
The packet sniffer also formats and presents multi-line data for easier readability.

Version 2: CodeAlpha_Network_Packet_Sniffer_with_Log_Files.py

This version of the packet sniffer logs packet information into a file named "packet_sniffer.log". 
The logging is controlled by user input. 
Entering 'start' begins the packet sniffing process, and 'stop' ends it. 
The captured packets are logged in a detailed format, including a timestamp for each entry. 
The code uses multi-threading to allow the sniffer to run in the background, while logging continues until explicitly stopped.
