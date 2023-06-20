from scapy.all import ARP, Ether, srp
import threading
import requests

def get_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.content.decode()
    return "Unknown"

def arp_scan(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        vendor = get_vendor(received.hwsrc)
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'vendor': vendor
        })

    return devices

def arp_scan_threaded(ip_addresses):
    devices = []

    for ip in ip_addresses:
        result = arp_scan(ip)
        devices.extend(result)

    return devices

def arp_scan_multi_threaded(ip_range, num_threads=16):
    devices = []

    # Generate the list of IP addresses to scan
    ip_addresses = [f"192.168.1.{i}" for i in range(ip_range[0], ip_range[1] + 1)]

    # Split the IP addresses into equal segments for each thread
    segment_size = len(ip_addresses) // num_threads

    # Create and start threads
    threads = []
    for i in range(num_threads):
        start = i * segment_size
        end = (i + 1) * segment_size

        # Adjust the end index for the last thread
        if i == num_threads - 1:
            end = len(ip_addresses)

        thread = threading.Thread(target=lambda: devices.extend(arp_scan_threaded(ip_addresses[start:end])))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return devices

# Perform the ARP scan for IP range 192.168.1.0 to 192.168.1.255
ip_range = (0, 255)
devices = arp_scan_multi_threaded(ip_range)

# Print the discovered devices
print("IP\t\t\tMAC Address\t\tVendor")
print("-----------------------------------------")
for device in devices:
    print(f"{device['ip']}\t{device['mac']}\t{device['vendor']}")
