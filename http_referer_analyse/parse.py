import dpkt
import datetime
import socket

f = open('http.pcap')
pcap = dpkt.pcap.Reader(f)
mylist = []

# For each packet in the pcap process the contents
for timestamp, buf in pcap:

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)

    # Make sure the Ethernet data contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
        continue

    # Now grab the data within the Ethernet frame (the IP packet)
    ip = eth.data

    # Check for TCP in the transport layer
    if isinstance(ip.data, dpkt.tcp.TCP):

        # Set the TCP data
        tcp = ip.data

        # Now see if we can parse the contents as a HTTP request
        try:
            request = dpkt.http.Request(tcp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue

        # get http referer
        myhttp = request.headers
        if 'referer' in myhttp:
            mylist.append(myhttp['referer'])

f.close()

tempitem = mylist[0]
mynewlist = [tempitem]
# filter css and js request
for index, item in enumerate(list(filter(lambda x : x[-3:]!='css' and x[-2:]!='js' , mylist))):
    if index == 0:
        continue
    if item == tempitem:
        continue
    else:
        mynewlist.append(item)
        tempitem = item

print mynewlist
