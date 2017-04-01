import dpkt
import datetime
import socket

f = open('http.pcap')
pcap = dpkt.pcap.Reader(f)
mylist = []

for timestamp, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)

    # test is this eth packet contains a ip packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
        continue

    ip = eth.data
    if isinstance(ip.data, dpkt.tcp.TCP):
        # Set the TCP data
        tcp = ip.data
        # if the contents is a HTTP request
        try:
            request = dpkt.http.Request(tcp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue
        # check if it is the first http request of a new website
        if request.uri == '/':
            myheaders = request.headers
            if 'referer' in myheaders:
                print 'host: %s\treferer: %s' % \
                    (myheaders['host'], myheaders['referer'])
            else:
                print 'host: %s' % myheaders['host']

f.close()
