from scapy.all import sniff

def packet_handler(packet):
    try:
        #Check for IP layer
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst

            #Check for TCP or UDP layer
            if packet.haslayer('TCP'):
                protocol = "TCP"
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
            elif packet.haslayer('UDP'):
                protocol = "UDP"
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport
            else:
                protocol = "Unknown"  #Handle cases where it's neither TCP nor UDP

            if protocol != "Unknown":
                print(f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} ({protocol})")

    except Exception as e:
        print(f"An error occurred: {e}")

try:
    sniff(prn=packet_handler, count=10)
except Exception as e:
    print(f"An error occurred while sniffing: {e}")
