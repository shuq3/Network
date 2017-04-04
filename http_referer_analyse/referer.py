import dpkt
import datetime
import socket

f = open('http.pcap')
pcap = dpkt.pcap.Reader(f)
myrequest = {}
myindex = []

for timestamp, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
        continue

    ip = eth.data

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        try:
            request = dpkt.http.Request(tcp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue

        # get http referer
        myheaders = request.headers
        if 'accept' in myheaders:
            mytype = request.headers['accept'];
            if mytype.find("text/html")!= -1 and mytype.find("application/xhtml+xml")!= -1:
                myindex.append(timestamp)

        if 'referer' in myheaders :
            myreferer = myheaders['referer']
            refererlength = len(myreferer)
            if myreferer[refererlength-4:] != ".css" and myreferer[refererlength-3:] != ".js":
                if myheaders['referer'] in myrequest:
                    myrequest[myheaders['referer']] += 1
                else:
                    myrequest[myheaders['referer']] = 1

myrequest = {k: v for k, v in myrequest.items() if v > 1}
# sort = sorted(myrequest.items(), key=operator.itemgetter(1), reverse = True)
# print sort
f.close()

f = open('http.pcap')
pcap = dpkt.pcap.Reader(f)
for timestamp, buf in pcap:
    if len(myindex) > 0 and timestamp == myindex[0]:
        myindex.pop(0)
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        request = dpkt.http.Request(tcp.data)
        if request.uri == '/':
            print request
        else:
            urilength = len(request.uri)
            for keyuri in myrequest.keys():
                if (keyuri[len(keyuri)-urilength:] == request.uri):
                    print request

f.close()
