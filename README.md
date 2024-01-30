<h1>I. Introduction</h1>

The Network Scanner Utility is a Python application designed to address the paramount concern of network security in today's interconnected world. It offers effective analysis and monitoring tools to examine networks, detect connected devices, identify open ports, and assess potential security risks. Its significance spans across individuals, small businesses, and large organizations, all seeking to safeguard their digital environments. Leveraging established libraries like Scapy and Nmap, this utility ensures thorough and accurate scanning. Key features, an intuitive user interface, and practical recommendations for enhancing network security are highlighted, aiming to provide transparency, control, and confidence in network security management. Welcome to the world of the Network Scanner Utility!

<h1>II. Objectifs</h1>

The objectives for enhancing the Network Scanner Utility include:

1. Improve security assessment capabilities with additional checks for vulnerabilities.
2. Expand port coverage for a more comprehensive evaluation of network security.
3. Integrate threat intelligence feeds to identify malicious IP addresses and emerging threats.
4. Implement user authentication checks to identify weak credentials.
5. Introduce automated periodic scans for monitoring network changes.
6. Enhance reporting with graphical representations and trend analysis.
7. Extend platform compatibility beyond Windows.
8. Integrate real-time alerts for critical security events.
9. Optimize performance for faster and scalable network assessments.
10. Encourage community contributions and collaboration on platforms like GitHub.

These enhancements aim to make the Network Scanner Utility more versatile and effective in addressing cybersecurity challenges.

<h1>III. Application Overview</h1>

The Network Scanner Utility application employs a Tkinter graphical interface to offer users a user-friendly platform for scanning devices on a network. It operates through two main methods:

1. **Scanning Devices:** The `scan_devices` function utilizes the Address Resolution Protocol (ARP) along with the Scapy library to send ARP broadcast requests, discovering the IP and MAC addresses of active devices in the network.

2. **Scanning Ports:** The `scan_ports` function employs the Nmap library to scan for open ports on a specific device. It utilizes an object of type `nmap.PortScanner` to initiate a scan on the device's IP address with specified options, analyzing the scan results to identify open ports and associated services.

In essence, the scanning process begins with ARP to detect active devices in the network. Then, each detected device undergoes individual analysis with Nmap to identify open ports and running services. This information is pivotal in assessing security risks associated with each device, including the examination of critical network services like SSH, HTTP, and others.

 - Scanning a specific IP for a specific open port:

<img width="341" alt="image" src="https://github.com/marwa2412/network-scanner/assets/86896531/c6258af5-0ea7-4b3f-87dc-185801587d98">

The code implements a network scanning program with a graphical user interface using Tkinter. When the user enters an IP address range and a port range, the program sends ARP requests to discover active devices in the network using Scapy. 
Subsequently, for each discovered device, it utilizes the nmap library to scan for open ports and evaluates the associated security risks for those ports. The scanning results, including device information, open ports, and security risks, are displayed in a Tkinter text area. 
Users can generate a textual report based on these results and open the last generated report. The application also employs visual features, such as colorcoding risks based on their severity, to enhance the readability of the results presented 
in the graphical interface.

<h1>IV. Conclusion</h1>

This Python program is a network scanner utility featuring a graphical user interface (GUI) built using the Tkinter library. Users can scan a specified IP range for devices, identify open ports, and assess potential security risks associated with these ports. The GUI includes input fields for IP and port ranges, buttons to initiate scans and refresh the interface, a text widget for displaying results, and a button to open the latest scan report.

The scanning process involves sending ARP requests to discover devices and then scanning open ports using the nmap library. The program checks for specific ports like SSH, HTTP, HTTPS, FTP, Telnet, SMTP, DNS, SMB, etc., and displays identified risks with color-coded levels. It generates timestamped text reports detailing scan results and allows users to open the latest report.

This utility provides a powerful and user-friendly solution for network reconnaissance. Its GUI, built with Tkinter, facilitates scanning, device identification, and security risk assessment. Color-coded risk display enhances clarity, while timestamped reports enable tracking network changes over time.

Targeting network administrators, security professionals, and enthusiasts, the program leverages scapy and nmap libraries for efficient scanning and port analysis. Future enhancements may include additional security checks, integration with vulnerability databases, or support for advanced network configurations. Nevertheless, the current version serves as a robust solution for basic scanning and lays the groundwork for future development, showcasing Python's efficacy in creating accessible cybersecurity tools.

