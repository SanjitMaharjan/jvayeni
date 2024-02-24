import tkinter as tk
from tkinter import ttk
import socket
import struct
import threading
import time

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # Initialize search boxes
        self.initialize_search_boxes()

        # Initialize data table
        self.initialize_data_table()

        # Create buttons
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=2, column=0, padx=10, pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=2, column=1, padx=10, pady=5)

        self.running = False
        self.packet_counter = 0

    def initialize_search_boxes(self):
        # Create search boxes
        self.search_box = tk.Entry(self.root);
        self.search_box.grid(row=0, column=0, padx=10, pady=5);

        # self.src_ip_search_entry = tk.Entry(self.root)
        # self.src_ip_search_entry.grid(row=0, column=0, padx=10, pady=5)

        # self.dst_ip_search_entry = tk.Entry(self.root)
        # self.dst_ip_search_entry.grid(row=0, column=1, padx=10, pady=5)

        # self.src_mac_search_entry = tk.Entry(self.root)
        # self.src_mac_search_entry.grid(row=0, column=2, padx=10, pady=5)

        # self.dst_mac_search_entry = tk.Entry(self.root)
        # self.dst_mac_search_entry.grid(row=0, column=3, padx=10, pady=5)

        # Bind search events
        self.search_box.bind("<KeyRelease>", self.search_all)
        # self.src_ip_search_entry.bind("<KeyRelease>", self.search_src_ip)
        # self.dst_ip_search_entry.bind("<KeyRelease>", self.search_dst_ip)
        # self.src_mac_search_entry.bind("<KeyRelease>", self.search_src_mac)
        # self.dst_mac_search_entry.bind("<KeyRelease>", self.search_dst_mac)
        # self.src_mac_search_entry.bind("<KeyRelease>", self.search_src_mac)
        # self.dst_mac_search_entry.bind("<KeyRelease>", self.search_dst_mac)

    def initialize_data_table(self):
        self.tree = ttk.Treeview(self.root, columns=("Packet No.", "Time", "Source IP", "Destination IP", "Source MAC", "Destination MAC"), show="headings")
        self.tree.heading("Packet No.", text="Packet No.", command=lambda: self.sort_column("Packet No."))
        self.tree.heading("Time", text="Time", command=lambda: self.sort_column("Time"))
        self.tree.heading("Source IP", text="Source IP", command=lambda: self.sort_column("Source IP"))
        self.tree.heading("Destination IP", text="Destination IP", command=lambda: self.sort_column("Destination IP"))
        self.tree.heading("Source MAC", text="Source MAC", command=lambda: self.sort_column("Source MAC"))
        self.tree.heading("Destination MAC", text="Destination MAC", command=lambda: self.sort_column("Destination MAC"))
        self.tree.grid(row=1, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

        self.tree.column("Packet No.", width=100)
        self.tree.column("Time", width=150)
        self.tree.column("Source IP", width=150)
        self.tree.column("Destination IP", width=150)
        self.tree.column("Source MAC", width=150)
        self.tree.column("Destination MAC", width=150)

        self.tree_scroll = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.tree_scroll.set)
        self.tree_scroll.grid(row=1, column=4, sticky="ns")

    def start_sniffing(self):
        if not self.running:
            self.running = True
            self.packet_counter = 0
            threading.Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        self.running = False

    def sniff_packets(self):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while self.running:
            try:
                raw_data, addr = conn.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
                if eth_proto == 8:
                    (version, header_length, ttl, proto, src, target, data) = self.ipv4_packet(data)
                    self.packet_counter += 1
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.tree.insert("", "end", values=(self.packet_counter, timestamp, src, target, src_mac, dest_mac))
            except:
                continue

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.ntohs(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def sort_column(self, column):
        data = [(self.tree.set(child, column), child) for child in self.tree.get_children('')]
        data.sort(reverse=self.tree.heading(column)["text"] == column)
        for index, item in enumerate(data):
            self.tree.move(item[1], '', index)
        self.tree.heading(column, text=column, command=lambda: self.sort_column(column))

    def search_src_ip(self, event):
        self.search(self.src_ip_search_entry, "Source IP")

    def search_dst_ip(self, event):
        self.search(self.dst_ip_search_entry, "Destination IP")

    def search_src_mac(self, event):
        self.search(self.src_mac_search_entry, "Source MAC")

    def search_dst_mac(self, event):
        self.search(self.dst_mac_search_entry, "Destination MAC")

    def search_all(self, event):
        self.search(self.search_box)

    def search(self, entry, column=""):
        search_term = entry.get().lower()
        print(search_term)
        items = self.tree.get_children('')
        for item in items:
            if search_term.startswith('src_ip:'):
                search = search_term.replace('src_ip:','')
                if search in self.tree.item(item, 'values')[self.tree["columns"].index("Source IP")].lower():
                    self.tree_selection_add(item)
            elif search_term.startswith('dst_ip:') and search_term in self.tree.item(item, 'values')[self.tree["columns"].index("Destination IP")].lower():
                self.tree_selection_add(item)
            else:
                self.tree.selection_remove(item)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
