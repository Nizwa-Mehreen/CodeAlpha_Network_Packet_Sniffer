# Importing libraries needed 
import logging
from scapy.all import sniff
import threading

# Setup logging to save in "packet_sniffer.log"
logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Packet Sniffer Initialized")

# Global variable to control packet sniffer
stop_sniffing = threading.Event()

# Packet Sniffer Main Code
def network_packet_sniffer():
    logging.info("Packet Sniffer Started")
    # Sniffed packets are sent to process_packet function
    sniff(prn=process_packet, stop_filter=lambda p: stop_sniffing.is_set())
    logging.info("Packet Sniffer Stopped")

# Process each packet and log information
def process_packet(packet):
    logging.info(f"Packet captured: {packet.summary()}")

# Function to start sniffing in a separate thread
def start_sniffer():
    sniffer_thread = threading.Thread(target=network_packet_sniffer)
    sniffer_thread.start()
    return sniffer_thread

# Function to stop the sniffer
def stop_sniffer():
    stop_sniffing.set()

# Main control for starting and stopping the sniffer
def main():
    while True:
        choice = input("Enter 'start' to start sniffing, 'stop' to stop: ").strip().lower()
        
        if choice == 'start':
            if stop_sniffing.is_set():
                stop_sniffing.clear()  # Reset the stop flag
            sniffer_thread = start_sniffer()
        elif choice == 'stop':
            stop_sniffer()
            if 'sniffer_thread' in locals():
                sniffer_thread.join()  # Wait for the sniffer thread to finish
            break
        else:
            print("Invalid option. Please enter 'start' or 'stop'.")

main()
