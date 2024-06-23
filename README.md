# Packet Sniffer

Packet Sniffer is a Python application built with tkinter and scapy libraries to capture and display network packets. It allows you to monitor traffic on a selected network interface, view detailed information about captured packets, and save the captured data to a text file.

## Features

- **Interface Selection:** Choose from available network interfaces on your system to start packet sniffing.
- **Packet Details:** Display information such as source IP, destination IP, protocol (TCP/UDP), source port, destination port, and payload for each captured packet.
- **HTTP Support:** Identify and parse HTTP requests to display request method, host, path, user-agent, and payload.
- **Dark/Light Mode:** Switch between dark and light mode themes for better readability.
- **Save Data:** Save captured packet data to a text file for further analysis.

## Requirements

- Python 3.x
- Required Python packages: tkinter, scapy, psutil

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd Packet-Sniffer
