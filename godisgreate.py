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

        # Initialize UI
        self.initialize_ui()

        # Variables
        self.running = False
        self.packet_counter = 0

        self.show_placeholder()

    def initialize_ui(self):
        # Search Box
        self.search_box = tk.Entry(self.root)
        self.search_box.grid(
            row=0, column=0, columnspan=4, sticky="ew", padx=10, pady=5
        )
        self.search_box.insert(0, "Search...")
        self.search_box.bind("<FocusIn>", self.clear_placeholder)
        self.search_box.bind("<FocusOut>", self.restore_placeholder)
        self.search_box.bind("<KeyRelease>", self.search_all)

        # Data Table
        self.initialize_data_table()

        # Description Box
        self.desc_box = tk.Text(self.root, height=10, width=80)
        self.desc_box.grid(row=3, column=0, columnspan=4, padx=10, pady=5)

        # Buttons
        self.start_button = tk.Button(
            self.root, text="Start Sniffing", command=self.start_sniffing
        )
        self.start_button.grid(row=2, column=0, padx=10, pady=5)

        self.stop_button = tk.Button(
            self.root, text="Stop Sniffing", command=self.stop_sniffing
        )
        self.stop_button.grid(row=2, column=1, padx=10, pady=5)

    def initialize_data_table(self):
        all_columns = (
            "Packet No.",
            "Time",
            "Source IP",
            "Destination IP",
            "Source MAC",
            "Destination MAC",
            "Source Port",
            "Destination Port",
            # "Sequence",
            # "Acknowledgement",
            # "Flag_URG",
            # "Flag_ACK",
            # "Flag_PSH",
            # "Flag_RST",
            # "Flag_SYN",
            # "Flag_FIN",
        )
        visible_columns = ("Packet No.", "Time", "Source IP", "Destination IP", "Source MAC", "Destination MAC")
    
        # Create the treeview with all columns
        self.tree = ttk.Treeview(self.root, columns=all_columns, show="headings")
        for col in all_columns:
            self.tree.heading(col, text=col, command=lambda: self.sort_column(col))
        self.tree.grid(row=1, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

        # Set displaycolumns to show only visible columns
        self.tree["displaycolumns"] = visible_columns

        # self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        # for col in columns:
        #     self.tree.heading(col, text=col, command=lambda: self.sort_column(col))

        # self.tree = ttk.Treeview(self.root, columns=("Packet No.", "Time", "Source IP", "Destination IP", "Source MAC", "Destination MAC"), show="headings")
        # self.tree.heading("Packet No.", text="Packet No.", command=lambda: self.sort_column("Packet No."))
        # self.tree.heading("Time", text="Time", command=lambda: self.sort_column("Time"))
        # self.tree.heading("Source IP", text="Source IP", command=lambda: self.sort_column("Source IP"))
        # self.tree.heading("Destination IP", text="Destination IP", command=lambda: self.sort_column("Destination IP"))
        # self.tree.heading("Source MAC", text="Source MAC", command=lambda: self.sort_column("Source MAC"))
        # self.tree.heading("Destination MAC", text="Destination MAC", command=lambda: self.sort_column("Destination MAC"))
        # self.tree.grid(row=1, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

        for col in all_columns:
            self.tree.column(col, width=150)

        tree_scroll = ttk.Scrollbar(
            self.root, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscroll=tree_scroll.set)
        tree_scroll.grid(row=1, column=4, sticky="ns")

        self.tree.bind("<<TreeviewSelect>>", self.show_description)

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
                    (version, header_length, ttl, proto, src, target, data) = (
                        self.ipv4_packet(data)
                    )
                    self.packet_counter += 1
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    # self.tree.insert("", "end", values=(self.packet_counter, timestamp, src, target, src_mac, dest_mac))
                    self.tree.insert(
                        "",
                        "end",
                        values=(
                            self.packet_counter,
                            timestamp,
                            src,
                            target,
                            src_mac,
                            dest_mac,
                            "test",
                            "sanjit"
                        ),
                    )
            except:
                continue

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
        return (
            self.get_mac_addr(dest_mac),
            self.get_mac_addr(src_mac),
            socket.ntohs(proto),
            data[14:],
        )

    def get_mac_addr(self, bytes_addr):
        bytes_str = map("{:02x}".format, bytes_addr)
        return ":".join(bytes_str).upper()

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
        return (
            version,
            header_length,
            ttl,
            proto,
            self.ipv4(src),
            self.ipv4(target),
            data[header_length:],
        )

    def ipv4(self, addr):
        return ".".join(map(str, addr))

    def sort_column(self, column):
        current_heading = self.tree.heading(column, "text")
        data = [
            (self.tree.set(child, column), child)
            for child in self.tree.get_children("")
        ]
        data.sort(reverse=current_heading.startswith("-"))
        for index, item in enumerate(data):
            self.tree.move(item[1], "", index)
        if current_heading.startswith("-"):
            self.tree.heading(
                column, text=column, command=lambda col=column: self.sort_column(col)
            )
        else:
            self.tree.heading(
                column,
                text=f"-{column}",
                command=lambda col=column: self.sort_column(col),
            )

    def clear_placeholder(self, event):
        if self.search_box.get() == "Search...":
            self.search_box.delete(0, tk.END)

    def restore_placeholder(self, event):
        if not self.search_box.get():
            self.search_box.insert(0, "Search...")

    def search_all(self, event):
        self.search(self.search_box)

    def search(self, entry, column=""):
        search_term = entry.get().lower()
        print(search_term)
        items = self.tree.get_children("")
        for item in items:
            values = self.tree.item(item, "values")
            if values:
                if search_term.startswith("src_ip:"):
                    search = search_term.replace("src_ip:", "")
                    src_ip_index = self.tree["columns"].index("Source IP")
                    if values[src_ip_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                elif search_term.startswith("dst_ip:"):
                    search = search_term.replace("dst_ip:", "")
                    dst_ip_index = self.tree["columns"].index("Destination IP")
                    if values[dst_ip_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                elif search_term.startswith("src_mac:"):
                    search = search_term.replace("src_mac:", "")
                    src_mac_index = self.tree["columns"].index("Source MAC")
                    if values[src_mac_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                elif search_term.startswith("dst_mac:"):
                    search = search_term.replace("dst_mac:", "")
                    dst_mac_index = self.tree["columns"].index("Destination MAC")
                    if values[dst_mac_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                else:
                    self.tree.selection_remove(item)

    def show_placeholder(self):
        self.desc_box.delete("1.0", tk.END)
        self.desc_box.insert(tk.END, "Description")

    def show_description(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item, "values")
            description = "\n".join(
                [
                    f"{column}: {value}"
                    for column, value in zip(self.tree["columns"], values)
                ]
            )
            self.desc_box.delete("1.0", tk.END)
            self.desc_box.insert(tk.END, description)
        else:
            self.show_placeholder()


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
