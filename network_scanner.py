import argparse
import ipaddress
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Tk, Text, END, Button, Label, Entry
import nmap
from scapy.all import ARP, Ether, srp
import os

# Function to set the color scheme of the application
def set_app_colors():
    primary_color = "#1e3a8a"
    secondary_color = "#f5f5f5"
    accent_color = "#008080"
    root.configure(bg=secondary_color)
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TButton', foreground=secondary_color, background=primary_color)
    style.configure('TLabel', foreground=primary_color, background=secondary_color)
    style.configure('TEntry', fieldbackground=secondary_color, foreground=primary_color)

# Function to generate a report based on scanned devices and security risks
def generate_report(devices, security_risks):
        # Generate the current timestamp in the desired format
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        # Create the filename for the report with a timestamp
    report_filename = f'C:\\Users\\elarf\\Downloads\\network_scan_reports\\network_scan_report_{timestamp}.txt'
        # Open the report file for writing using the 'with' statement to ensure proper handling of the file
    with open(report_filename, 'w') as report_file:
        # Write the header of the report
        report_file.write("Network Scan Report\n")
        report_file.write(f"Scan Time: {timestamp}\n\n")
        # Write information about scanned devices
        report_file.write("Scanned Devices:\n")
        for device in devices:
            report_file.write(f"IP: {device['ip']}, MAC: {device['mac']}\n")
        report_file.write("\n")
        # Write information about ports and security risks
        report_file.write("Ports & Security Risks:\n")
        if security_risks:
            # If security risks are present, iterate through them and write details
            for risk in security_risks:
                report_file.write(f"IP: {risk['ip']}, Port: {risk['port']}, Level: {risk['level']}, Message: {risk['message']}\n")
        else:
            # If no security risks are found, indicate that in the report
            report_file.write("No security risks found.\n")
    return report_filename

# Function to open the last generated report
def open_last_report():
    # Define the directory where reports are stored
    report_directory = 'C:\\Users\\elarf\\Downloads\\network_scan_reports'
    # Get a list of all files in the directory that start with 'network_scan_report_'
    reports = [f for f in os.listdir(report_directory) if f.startswith('network_scan_report_')]
    # Check if there are any reports
    if reports:
        # Find the latest report based on creation time
        last_report = max(reports, key=lambda x: os.path.getctime(os.path.join(report_directory, x)))
        # Construct the full path to the last report
        last_report_path = os.path.join(report_directory, last_report)
        # Open the last report using Notepad
        os.system(f'start notepad.exe "{last_report_path}"')
    else:
        # If no reports are found, display a message and update a text widget (assuming result_text is a tkinter Text widget)
        result_text.insert(tk.END, "No reports found.\n")
        messagebox.showerror("No reports found", "There is no previous reports")
        result_text.update_idletasks()

# Function to verify if the input is a valid IP address or CIDR notation
def is_valid_ip(ip):
    try:
        # Attempt to create an IP network object from the input
        ipaddress.ip_network(ip, strict=False)
        # If successful, consider the input as a valid IP address or CIDR notation
        return True
    except ValueError:
        # If a ValueError is caught, the input is not a valid IP address or CIDR notation
        return False

# Function to verify if the input is a valid port number
def is_valid_port(port):
    try:
        if '-' in port:
            # Handle the format "66-90": Check if the range is valid (0 to 65535) and start is less than or equal to end
            start, end = map(int, port.split('-'))
            return 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
        elif ',' in port:
            # Handle the format "66,77": Check if all individual ports in the list are valid (0 to 65535)
            ports = map(int, port.split(','))
            return all(0 <= p <= 65535 for p in ports)
        else:
            # Handle the format "66": Check if the single port is valid (0 to 65535)
            port = int(port)
            return 0 <= port <= 65535
    except ValueError:
        # If a ValueError is caught during conversion or validation checks, the input is not a valid port number
        return False

# Function to scan devices in the network using ARP
def scan_devices(ip_range):
    # List to store information about discovered devices
    devices = []

    # Create an ARP request packet for the specified IP range
    arp_request = ARP(pdst=ip_range)

    # Create an Ethernet frame with the broadcast MAC address
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the Ethernet frame and ARP request to form the complete packet
    packet = ether / arp_request

    # Send the packet using scapy's srp function, wait for responses for 3 seconds, and retry twice
    result = srp(packet, timeout=3, verbose=0, retry=2)[0]

    # Check if no devices are found and display a message box
    if not result:
        messagebox.showinfo("No Devices Found in the network", f"Can't scan the network with IP range: {ip_range}")

    # Iterate through the responses and extract information about discovered devices
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'risks': []})

    # Return the list of discovered devices
    return devices

# Function to scan open ports on a target IP
def scan_ports(target_ip, port_range):
    # Create an instance of the nmap.PortScanner class
    scanner = nmap.PortScanner()
    # Scan the target IP for open ports within the specified range using service version detection
    scanner.scan(target_ip, arguments=f"-p {port_range} -sV")
    # Dictionary to store information about open ports and associated services
    open_ports = {}
    # Iterate through each host in the scan results
    for host in scanner.all_hosts():
        # Iterate through each protocol for the current host
        for proto in scanner[host].all_protocols():
            # Retrieve the list of open ports for the current protocol and host
            ports = scanner[host][proto].keys()
            # Iterate through each port for the current host and protocol
            for port in ports:
                # Get the state (open/closed) of the current port
                state = scanner[host][proto][port]['state']
                # Check if the port is open
                if state == 'open':
                    # Extract service information for open ports
                    service = scanner[host][proto][port]['name']
                    # Add the open port and its associated service to the open_ports dictionary
                    open_ports[port] = service
    # Return a tuple containing the dictionary of open ports and the scanner object
    return open_ports, scanner

# Function to check security risks based on open ports
def check_security_risks(open_ports, scanner, target_ip):
    security_risks = []
    risk_level = ""
    message = ""
    for port, service in open_ports.items():
        if int(port) == 22 and service.lower() == 'ssh':
            risk_level = "high"
            message = "SSH port is open. Ensure secure configurations. Service Version: {}".format(scanner[scanner.all_hosts()[0]]['tcp'][int(port)]['version'])
        elif int(port) == 80 and (service.lower() == 'http' or service.lower() == 'www'):
            risk_level = "medium"
            message = "HTTP port is open. Check for web vulnerabilities. Service Version: {}".format(scanner[scanner.all_hosts()[0]]['tcp'][int(port)]['version'])
        elif int(port) == 443 and (service.lower() == 'https' or 'ssl' in service.lower() or 'http' in service.lower()):
            risk_level = "high"
            message = "HTTPS port is open. Check for secure configurations. Service Version: {}".format(scanner[scanner.all_hosts()[0]]['tcp'][int(port)]['version'])
        elif int(port) == 21:
            risk_level = "medium"
            message = "FTP port is open. Check FTP configurations. Service Version: {}".format(scanner[scanner.all_hosts()[0]]['tcp'][int(port)]['version'])
        elif int(port) == 23:
            risk_level = "critical"
            message = "Telnet port is open. Avoid using Telnet for security reasons. Service Version: {}".format(scanner[scanner.all_hosts()[0]]['tcp'][int(port)]['version'])
        elif int(port) == 25:
            risk_level = "medium"
            message = "SMTP port is open. Check email server configurations. Service Version: {}".format(scanner[scanner.all_hosts()[0]]['tcp'][int(port)]['version'])
        elif int(port) == 53:
            risk_level = "low"
            message = "DNS port is open. This port is associated with the Domain Name System (DNS) service, which is crucial for translating domain names to IP addresses. Verify the security configuration of your DNS server. Check for proper access controls, DNSSEC implementation, and ensure the server is updated with the latest security patches. Review logs for any suspicious activities. Service Version: {}".format(scanner[scanner.all_hosts()[0]]['tcp'][int(port)]['version'])
        elif int(port) == 445:
            risk_level = "critical"
            message = "Port 445 is open. Microsoft-DS (Directory Services) is associated with file and printer sharing on Windows networks. Ensure that the SMB (Server Message Block) protocol is securely configured. Check for proper access controls and consider the latest security best practices to prevent potential vulnerabilities and unauthorized access."
        elif int(port) == 135:
            risk_level = "critical"
            message = "Port 135 is open. This port is associated with Microsoft's Distributed Component Object Model (DCOM) and Remote Procedure Call (RPC) service. Ensure that the service is securely configured and updated to mitigate potential vulnerabilities."
        elif int(port) == 139:
            risk_level = "high"
            message = "Port 139 is open. This port is associated with the NetBIOS Session Service, commonly used for file and printer sharing in Windows environments. Ensure secure configurations and restrict access to prevent potential vulnerabilities."
        elif int(port) == 902:
            risk_level = "high"
            message = "Port 902 is open. This port is associated with VMware Server Management. Ensure secure configurations and restrict access to prevent potential vulnerabilities."
        security_risks.append({'ip': target_ip, 'port': port, 'level': risk_level, 'message': message})
    return security_risks

# Function to scan the network, display results, and generate a report
def scan_network(ip_range, port_range, result_text):
    # Scan devices in the network
    devices = scan_devices(ip_range)

    # Configure font style for the report
    result_text.tag_configure("report", font=("Calibri", 12, "bold"))

    # Display the header for scanning devices
    result_text.insert(tk.END, "\nScanning Devices in the network:\n", "report")
    result_text.update_idletasks()

    # List to store all identified risks across devices
    all_risks = []

    # Iterate through discovered devices
    for device in devices:
        # Display device information
        result_text.insert(tk.END, f"\n ► IP: {device['ip']}, MAC: {device['mac']}\n")
        result_text.update_idletasks()

        # Underline device information
        result_text.tag_configure("underline", underline=True)

        # Scan open ports for the current device
        open_ports, scanner = scan_ports(device['ip'], port_range)

        # Display open ports for the current device
        result_text.insert(tk.END, f"Open ports:\n", "underline")
        result_text.update_idletasks()

        # Check if open ports are found
        if open_ports:
            for port in open_ports:
                result_text.insert(tk.END, f" • Port: {port}, Service: {open_ports[port]}\n")
                result_text.update_idletasks()
        else:
            result_text.insert(tk.END, " • No open ports found.\n")
            result_text.update_idletasks()

        # Check security risks for the current device
        device_risks = check_security_risks(open_ports, scanner, device['ip'])

        # Display risks for the current device
        result_text.insert(tk.END, "Risks for this device:\n", "underline")
        result_text.update_idletasks()

        # Iterate through identified risks for the current device
        for risk in device_risks:
            # Check if a risk level is specified
            if risk['level'] != "":
                # Configure color tags for risk levels
                result_text.tag_configure("port&risk_level_label", foreground='blue')
                result_text.tag_configure("critical_label", foreground='red')
                result_text.tag_configure("high_label", foreground='orange')
                result_text.tag_configure("medium_label", foreground='yellow')
                result_text.tag_configure("low_label", foreground='green')
                result_text.update_idletasks()

                # Extract risk details
                port = risk['port']
                level = risk['level']
                message = risk['message']

                # Display risk information with appropriate color coding
                if level == "critical":
                    color_tag = 'critical_label'
                elif level == "high":
                    color_tag = 'high_label'
                elif level == "medium":
                    color_tag = 'medium_label'
                elif level == "low":
                    color_tag = 'low_label'
                result_text.insert(tk.END, f"\tPort:  ", "port&risk_level_label")
                result_text.insert(tk.END, f"{port}", )
                result_text.insert(tk.END, ", ")
                result_text.update_idletasks()
                result_text.insert(tk.END, "\n\tRisk Level: ", "port&risk_level_label")
                result_text.insert(tk.END, f"{level}")
                result_text.insert(tk.END, ", ")
                result_text.update_idletasks()
                result_text.insert(tk.END, "\n\tMessage: ","port&risk_level_label")
                result_text.insert(tk.END, f"{message}", color_tag)
                result_text.update_idletasks()
                result_text.insert(tk.END, "\n\t---------------------------------------------------------------------\n", "report")

                # Append the risk to the list of all risks
                all_risks.extend(device_risks)
            else:
                result_text.insert(tk.END, "  No security risks found.\n")
                result_text.update_idletasks()

    # Return the list of discovered devices and all identified risks
    return devices, all_risks

# Function to refresh the input fields and result text
def refresh():
    # Clear the content of the IP entry field
    ip_entry.delete(0, tk.END)
    # Clear the content of the port entry field
    port_entry.delete(0, tk.END)
    # Clear the content of the result text widget
    result_text.delete(1.0, tk.END)

# Function to start the network scan
def start_scan():
    # Get the IP range and port range from the input fields
    ip_range = ip_entry.get()
    port_range = port_entry.get()
    # Validate the input IP address
    if not is_valid_ip(ip_range):
        messagebox.showerror("Invalid IP", "IP address is empty or in an invalid format. Please verify your input.")
        return
    # Validate the input port number
    if not is_valid_port(port_range):
        messagebox.showerror("Invalid Port", "Port input is empty or in an invalid format. Please verify your input.")
        return
    # Clear the content of the result text widget
    result_text.delete(1.0, tk.END)
    # Perform the network scan and retrieve results
    devices, security_risks = scan_network(ip_range, port_range, result_text)
    # Generate a report based on the scan results
    report_filename = generate_report(devices, security_risks)
    # Display a message indicating that the report has been generated
    result_text.insert(tk.END, f"\nReport generated: {report_filename}\n", "report")


# Function to set the default font for the result text
def set_default_font(widget, font_family, font_size, font_weight):
    # Configure a tag named "default" with the specified font parameters
    widget.tag_configure("default", font=(font_family, font_size, font_weight))

# Main Tkinter window
root = tk.Tk()
root.title("Network Scanner Utility")

# GUI elements
ip_label = ttk.Label(root, text="IP Range (X.X.X.X or CIDR):")
ip_label.pack()

ip_entry = ttk.Entry(root)
ip_entry.pack()

port_label = ttk.Label(root, text="Port Range :")
port_label.pack()

port_entry = ttk.Entry(root)
port_entry.pack()

scan_button = ttk.Button(root, text="Scan Network", command=start_scan)
scan_button.pack(pady=(10, 3))

refresh_button = ttk.Button(root, text="Refresh", command=refresh)
refresh_button.pack(pady=10)

result_text = tk.Text(root, wrap=tk.WORD, height=20, width=80)
result_text.pack()

open_report_button = ttk.Button(root, text="Open Last Report", command=open_last_report)
open_report_button.pack(pady=10)

set_default_font(result_text, "Calibri", 10, "bold")
set_app_colors()

root.mainloop()