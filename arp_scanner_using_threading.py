from scapy.all import ARP, Ether, srp
import threading
import socket

def arp_scan(ip_range):
    devices = []
    lock = threading.Lock()

    def get_device_info(ip, mac):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = 'N/A'
        vendor = get_vendor(mac)
        return hostname, vendor

    def get_vendor(mac):
        # Make an API call or use a local database to lookup the vendor based on MAC address
        # Replace the implementation below with your own logic
        return 'N/A'

    def scan(ip):
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=1, verbose=0)[0]
        for _, received in result:
            with lock:
                device_info = get_device_info(received.psrc, received.hwsrc)
                devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'hostname': device_info[0], 'vendor': device_info[1]})

    threads = []
    for i in range(1, 193):
        ip = f"192.168.1.{i}"
        thread = threading.Thread(target=scan, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Print the discovered devices
    print("IP\t\t\tMAC Address\t\t\tHostname\t\tVendor")
    print("-----------------------------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}\t{device['hostname']}\t{device['vendor']}")

# Example usage:
arp_scan("192.168.1.0/24")
