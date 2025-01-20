import curses
from scapy.all import *
import time
import threading
from datetime import datetime

def format_header(packet):
    """Formats the IP and TCP header details."""
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return "No IP/TCP Layer Found."

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    ip_details = f"""
IP Header
   |-IP Version        : {ip_layer.version}
   |-IP Header Length  : {ip_layer.ihl} DWORDS or {ip_layer.ihl * 4} Bytes
   |-Type Of Service   : {ip_layer.tos}
   |-IP Total Length   : {ip_layer.len} Bytes (Size of Packet)
   |-Identification    : {ip_layer.id}
   |-TTL               : {ip_layer.ttl}
   |-Protocol          : {ip_layer.proto}
   |-Checksum          : {ip_layer.chksum}
   |-Source IP         : {ip_layer.src}
   |-Destination IP    : {ip_layer.dst}
"""

    tcp_details = f"""
TCP Header
   |-Source Port        : {tcp_layer.sport}
   |-Destination Port   : {tcp_layer.dport}
   |-Sequence Number    : {tcp_layer.seq}
   |-Acknowledge Number : {tcp_layer.ack}
   |-Header Length      : {tcp_layer.dataofs} DWORDS or {tcp_layer.dataofs * 4} Bytes
   |-Urgent Flag        : {tcp_layer.flags.U}
   |-Acknowledgement Flag: {tcp_layer.flags.A}
   |-Push Flag          : {tcp_layer.flags.P}
   |-Reset Flag         : {tcp_layer.flags.R}
   |-Synchronise Flag   : {tcp_layer.flags.S}
   |-Finish Flag        : {tcp_layer.flags.F}
   |-Window Size        : {tcp_layer.window}
   |-Checksum           : {tcp_layer.chksum}
   |-Urgent Pointer     : {tcp_layer.urgptr}
"""

    ip_dump = hexdump(raw(ip_layer), dump=True)
    tcp_dump = hexdump(raw(tcp_layer), dump=True)
    payload = hexdump(raw(tcp_layer.payload), dump=True) if tcp_layer.payload else "No Data Payload"

    data_details = f"""
                        DATA Dump                         
IP Header
{ip_dump}

TCP Header
{tcp_dump}

Data Payload
{payload}
"""

    return ip_details + tcp_details + data_details

def curses_app(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)

    packets = []
    sniffing = False
    selected_idx = 0
    max_display = 0
    max_detail_lines = 20
    detail_offset = 0
    stop_sniffing_event = threading.Event()

    # Colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_CYAN)

    def sniff_packets():
        """Sniff packets and store them in the packets list."""
        def packet_handler(packet):
            if packet.haslayer(IP) and packet.haslayer(TCP):
                packets.append(packet)
                if len(packets) > 500:
                    packets.pop(0)

        sniff(prn=packet_handler, filter="tcp", store=0, stop_filter=lambda _: stop_sniffing_event.is_set())

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        max_display = height - 8

        serial_width = max(10, width // 12)
        date_width = max(20, width // 6)
        src_width = max(20, width // 6)
        dst_width = max(20, width // 6)
        port_width = max(10, width // 12)

        stdscr.addstr(1, 0, " " * (width // 2 - 7) + "Packet Sniffer" + " " * (width // 2 - 7),curses.A_BOLD | curses.color_pair(3))
        stdscr.addstr(height - 2, 0, "   Press 'q' to Quit | 's' to Start | 'e' to Stop | 'g' to go to bottom row", curses.color_pair(2))
        stdscr.addstr(height - 2, width - 18, f"Status : {'Started' if sniffing else 'Stopped'}", curses.color_pair(2))

        stdscr.attron(curses.color_pair(1))
        stdscr.border(0, 0, 0, 0, 0, 0, 0, 0)
        stdscr.attroff(curses.color_pair(1))

        stdscr.addstr(3, 2, f"{' ':<{serial_width}} {'Date Time':<{date_width}} {'Source':<{src_width}} {'Destination':<{dst_width}} {'Src Port':<{port_width}} {'Dst Port':<{port_width}} {'        '}", curses.A_BOLD | curses.A_DIM)

        if len(packets) > 0:
            start_idx = max(0, selected_idx - max_display + 1)
            end_idx = min(len(packets), start_idx + max_display)

            for i, packet in enumerate(packets[start_idx:end_idx]):
                row = 5 + i
                attr = curses.color_pair(1) if start_idx + i == selected_idx else curses.A_NORMAL
                packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                stdscr.addstr(
                    row, 2,
                    f"{' ':<{serial_width}} {packet_time:<{date_width}} {packet[IP].src:<{src_width}} {packet[IP].dst:<{dst_width}} {packet[TCP].sport:<{port_width}} {packet[TCP].dport:<{port_width}}",
                    attr
                )

        key = stdscr.getch()

        if key == ord('q'):
            stop_sniffing_event.set()
            break
        elif key == ord('s') and not sniffing:
            stop_sniffing_event.clear()
            sniffing = True
            threading.Thread(target=sniff_packets, daemon=True).start()
        elif key == ord('e') and sniffing:
            stop_sniffing_event.set()
            sniffing = False
        elif key == ord('g'):
            selected_idx = len(packets) - 1
        elif key == curses.KEY_DOWN and selected_idx < len(packets) - 1:
            selected_idx += 1
        elif key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == ord('\n'):
            if len(packets) > 0:
                details_view(stdscr, packets[selected_idx])
        elif key == ord('y'):
            if len(packets) > 0:
                draw_graph(stdscr)
        stdscr.refresh()



def details_view(stdscr, packet):
    """Function to show detailed packet information"""
    height, width = stdscr.getmaxyx()

    details = format_header(packet).splitlines()

    detail_offset = 0
    max_detail_lines = 22
    mid_y = height // 2 - max_detail_lines // 2

    mid_x = width // 2 - max(len(line) for line in details) // 2 - 4  # Shift left by 4 chars

    while True:
        stdscr.erase()

        stdscr.addstr(1, 0, ' ' * (width//2 - 13) + f"Packet Details                   " + ' ' * (width//2 - 21), curses.A_BOLD | curses.color_pair(3))
        stdscr.addstr(height - 2, 0, "   Press 'b' to go back", curses.color_pair(2))

        stdscr.attron(curses.color_pair(1))
        stdscr.border(0, 0, 0, 0, 0, 0, 0, 0)
        stdscr.attroff(curses.color_pair(1))

        for i in range(max_detail_lines):
            if detail_offset + i < len(details):
                stdscr.addstr(mid_y + i, mid_x, details[detail_offset + i])

        key = stdscr.getch()

        if key == ord('b'):
            break
        elif key == curses.KEY_DOWN and detail_offset + max_detail_lines < len(details):
            detail_offset += 1
        elif key == curses.KEY_UP and detail_offset > 0:
            detail_offset -= 1

        stdscr.refresh()
        

curses.wrapper(curses_app)
