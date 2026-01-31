from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
import re
#------------------------------------------------------------------------------------
#Test And Checking 'Is File Connected ?'
paket = rdpcap('test_flag.pcap')
print(f"Total Paket's Founded : {len(paket)}") # print the all paket's lenth 
#-----------------------------------------------------------------------------------
#Storing ALl IPs from Given File 
ips = set() # to avoid the repeated IP 

for pkt in paket:
    if 'IP' in pkt:
        ips.add(pkt[IP].src) # to add Pakets  scorce IP Address 
        ips.add(pkt[IP].dst) # To add Destination IP Address 

print("All IP Address :")
for ip in ips:
    print(f"{ip}")
#---------------------------------------------------------------------------------------
#Storing All ProtoCols 
protocol = set() # to Avoid the Repeated ProtoCols 

for pkg in paket:
    if pkg.haslayer(TCP):
        protocol.add("TCP")
    if pkg.haslayer(UDP):
        protocol.add('UDP')
    if pkg.haslayer(ICMP):
        protocol.add("ICMP")

print("All Protocols :- ")
for pt in protocol:
    print(f"{pt}")
#-----------------------------------------------------------------------------------------
# to Print Possible Flag 
Flagformet = input("Enter Flag Formet If You Konw (Example flag{....} -> input flag )")

if len(Flagformet) == 0:
    Flagformet = 'flag'  # useing the Bydefualt Formet
else:
    print(f"Your Flag Formet Is : {Flagformet}") # printing the Flag Formet
#---------------------------------------------------------------------------------------
# Searching The Flag Formet In Data  
for pkg in paket:
    if pkg.haslayer(TCP) and pkg.haslayer(Raw):
        playload = pkg[Raw].load
        try:
            text = playload.decode(errors="ignore")
            if Flagformet in text:
                print("Possible Flag:= ")
                print(text)
        except :
            print("!")
            break

#--------------------------------------------------------------------------------------
# printing All Readable Text 
print("----------Readable Text--------- ")
for pkg in paket:
    if pkg.haslayer(Raw):
        data = pkg[Raw].load

        strings = re.findall(rb"[ -~]{4,}", data)
        for s in strings:
            print(s.decode())       
