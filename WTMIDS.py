# -----------------------------------------------------------------------
#  second attempt 
# fully working code :)
import sys
import os
import threading
import time
import tkinter as tk
import winsound
from scapy.all import sniff, DNS, IP, TCP, UDP, ICMP

# Global variables
seen_queries = set()
suspicious_ips = set()
ip_port_counts = {}
is_monitoring = False
sniff_thread = None
current_time = time.strftime("%Y-%m-%d %H:%M:%S")
visited_websites = []  


def notify():
    try:
        winsound.Beep(900, 300)
    except RuntimeError:
        print("Beep sound failed.")

def show_popup(src_ip):
    popup = tk.Toplevel()
    popup.wm_title("Early detection")
    popup.geometry("400x150")
    label = tk.Label(popup, text=f"Suspicious activity detected from {src_ip} at {current_time}")
    label.pack(side="top", fill="x", pady=10)
    B1 = tk.Button(popup, text="Okay", command=popup.destroy)
    B1.pack(pady=10)
    popup.transient()
    popup.grab_set()
    popup.mainloop()

def handle_dns_packet(pkt):
    global current_time, visited_websites
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")

    if ICMP in pkt:
        src_ip = pkt[IP].src
        icmp_type = pkt[ICMP].type
        print(f"ICMP {icmp_type} packet from {src_ip}")

# Idhu bari web traffic based on DNS requests  
    if DNS in pkt and pkt[DNS].qd is not None:
        dns_query = pkt[DNS].qd.qname.decode('utf-8').lower()

        if dns_query.startswith("www.") or dns_query.startswith("in.") and "google" not in dns_query:
            if dns_query not in seen_queries:
                seen_queries.add(dns_query)
                entry = f"{dns_query} at {current_time}"
                visited_websites.append(entry)
                update_website_list(entry)
                print(entry)

#Idhu unknown ip na capture maadi store madkolodu 
    if IP in pkt:
        src_ip = pkt[IP].src

        if src_ip not in ip_port_counts:
            ip_port_counts[src_ip] = set()

        

        if TCP in pkt or UDP in pkt:
            src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
            ip_port_counts[src_ip].add(src_port)
            
            # Idhu malicious traffic pattern like ond 20 TCP packets bandre store madadhu 
            if len(ip_port_counts[src_ip]) > 20:
                if src_ip not in suspicious_ips:
                    suspicious_ips.add(src_ip)
                    print(f"Potential scanning activity detected from {src_ip} at {current_time}")
                    notify()
                    threading.Thread(target=show_popup, args=(src_ip,), daemon=True).start()

def update_website_list(entry):
    if website_listbox:
        website_listbox.insert(tk.END, entry)

# Idhu main function idhe capturing start madadu 
def start_monitoring():
    global is_monitoring, sniff_thread
    if not is_monitoring:
        is_monitoring = True
        # ide
        sniff_thread = threading.Thread(target=sniff, kwargs={"prn": handle_dns_packet, "filter": "tcp or udp or udp port 53", "store": False})
        sniff_thread.daemon = True
        sniff_thread.start()
        button.config(text="Stop Monitoring")

def stop_monitoring():
    global is_monitoring, sniff_thread
    if is_monitoring:
        is_monitoring = False
        if sniff_thread and sniff_thread.is_alive():
            sniff_thread = None
        button.config(text="Start Monitoring")
            
# idella button matte GUI ge
def toggle_monitoring():
    if is_monitoring:
        stop_monitoring()
    else:
        start_monitoring()

def create_gui():
    global button, website_listbox
    root = tk.Tk()
    root.title("Network Monitor")
    root.geometry("600x300")

    button = tk.Button(root, text="Start Monitoring", command=toggle_monitoring)
    button.pack(pady=10)

    tk.Label(root, text="Visited Websites:").pack()

    website_listbox = tk.Listbox(root, width=70, height=15)
    website_listbox.pack(pady=10)

    root.protocol("WM_DELETE_WINDOW", lambda: (stop_monitoring(), root.destroy()))

    root.mainloop()

if __name__ == "__main__":
    create_gui()
    # aste
# -------------------------------------------------------------------------------------------------------------

