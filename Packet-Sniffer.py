import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, Menu
from tkinter import filedialog as fd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import threading
import psutil

class PacketSniffer:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")

        self.dark_mode = False  # Default is light mode

        self.create_menu()

        self.label = tk.Label(master, text="Packet Sniffer", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.interface_label = tk.Label(master, text="Select Interface:")
        self.interface_label.pack(pady=5)

        self.interface_combo = ttk.Combobox(master, values=self.get_interfaces())
        self.interface_combo.pack(pady=5)

        self.text_area = scrolledtext.ScrolledText(master, width=100, height=30, wrap=tk.WORD, bg="#000", fg="#fff")
        self.text_area.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=10, pady=10)

        self.sniffing = False
        self.sniffer_thread = None

    def create_menu(self):
        menu_bar = Menu(self.master)
        self.master.config(menu=menu_bar)

        theme_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Light Mode", command=self.set_light_mode)
        theme_menu.add_command(label="Dark Mode", command=self.set_dark_mode)

        file_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save to File", command=self.save_to_file)

    def set_dark_mode(self):
        self.dark_mode = True
        self.master.config(bg="#333")
        self.label.config(bg="#333", fg="#fff")
        self.interface_label.config(bg="#333", fg="#fff")
        self.text_area.config(bg="#000", fg="#fff")
        self.start_button.config(bg="#444", fg="#fff")
        self.stop_button.config(bg="#444", fg="#fff")

    def set_light_mode(self):
        self.dark_mode = False
        self.master.config(bg="white")
        self.label.config(bg="white", fg="black")
        self.interface_label.config(bg="white", fg="black")
        self.text_area.config(bg="white", fg="black")
        self.start_button.config(bg="light gray", fg="black")
        self.stop_button.config(bg="light gray", fg="black")

    def get_interfaces(self):
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)

    def start_sniffing(self):
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showwarning("Input Error", "Please select a network interface.")
            return

        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, f"Starting packet sniffing on interface {interface}...\n")
        self.text_area.see(tk.END)

        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(interface,))
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.text_area.insert(tk.END, "Stopping packet sniffing...\n")
        self.text_area.see(tk.END)

       # save data
        if messagebox.askyesno("Save Data", "Do you want to save the captured data?"):
            self.save_to_file()

    def sniff_packets(self, interface):
        sniff(iface=interface, prn=self.process_packet, stop_filter=self.stop_filter)

    def stop_filter(self, packet):
        return not self.sniffing

    def process_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto

            protocol_name = {6: "TCP", 17: "UDP"}.get(protocol, "Other")

            info = f"Source IP: {src_ip}\n"
            info += f"Destination IP: {dst_ip}\n"
            info += f"Protocol: {protocol_name}\n"

            if protocol_name == "TCP" and TCP in packet:
                info += f"Source Port: {packet[TCP].sport}\n"
                info += f"Destination Port: {packet[TCP].dport}\n"
            elif protocol_name == "UDP" and UDP in packet:
                info += f"Source Port: {packet[UDP].sport}\n"
                info += f"Destination Port: {packet[UDP].dport}\n"

            payload = packet[IP].payload
            if payload:
                info += "Payload:\n"
                payload_lines = self.format_payload(payload)
                info += payload_lines

            info += "-" * 50 + "\n"  # Areee bhai bus line saparate kerne ke liye hai! 

            self.text_area.insert(tk.END, info + "\n")
            self.text_area.see(tk.END)

    def format_payload(self, payload):
        payload_str = str(payload)
        lines = [payload_str[i:i+80] for i in range(0, len(payload_str), 80)]
        formatted_payload = "\n".join(lines)
        return formatted_payload

    def save_to_file(self):
        file_path = fd.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not file_path:
            return
        
        with open(file_path, "w") as file:
            content = self.text_area.get("1.0", tk.END)
            file.write(content)


if __name__ == "__main__":
    root = tk.Tk()
    packet_sniffer = PacketSniffer(root)

    # windows adjust kerne liye code likha hai bro! Jyda dekh mat
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = int(screen_width * 0.8)
    window_height = int(screen_height * 0.8)
    window_x = (screen_width // 2) - (window_width // 2)
    window_y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")

    root.mainloop()
