import dpkt
import datetime
import socket

f = open('http.pcap')
pcap = dpkt.pcap.Reader(f)
attributes = []
timestamps = []
myindex = {}
referCount = {}
index = 0
mycount = 0
counter = 0

for timestamp, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
        continue

    ip = eth.data
    timestamps.append(timestamp)
    mycount += 1
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        try:
            request = dpkt.http.Request(tcp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue

        # get http request
        myrequest = {'request': request, 'timestamp': mycount-1}
        myindex[index] = myrequest

        # count referer
        if 'referer' in request.headers :
            myreferer = request.headers['referer']
            refererlength = len(myreferer)
            if request.headers['referer'] in referCount:
                referCount[myreferer] += 1
            else:
                referCount[myreferer] = 1

        index += 1

f.close()

for i in range(0, index):
    myheaders = myindex[i]['request'].headers
    myuri = myindex[i]['request'].uri
    attribute = {}
    attribute['index'] = i

    # accept
    if 'accept' in myheaders:
        mytype = myheaders['accept']
        if mytype.find("text/html")!= -1 :
            attribute['accept'] = 1
        elif mytype.find("application/")!= -1:
            attribute['accept'] = 2
        elif mytype.find("text/")!= -1:
            attribute['accept'] = 3
        elif mytype.find("image/")!= -1:
            attribute['accept'] = 4
        elif mytype.find("audio/")!= -1 or mytype.find("audio/")!= -1:
            attribute['accept'] = 5
        else:
            attribute['accept'] = 6
    else:
        attribute['accept'] = 0

    # uri
    if myuri == '/':
        attribute['uri'] = 1
    else:
        attribute['uri'] = 0

    # refer
    myhost = myheaders['host']
    if myhost in referCount:
        attribute['otherRefer'] = referCount[myhost]
    else:
        attribute['otherRefer'] = 0

    # timestamps
    nextCount = 0
    for j in range(myindex[i]['timestamp'], mycount):
        if timestamps[j] - timestamps[myindex[i]['timestamp']] < 0.1:
            nextCount += 1
        else:
            break
    attribute['nextPackets'] = nextCount

    preCount = 0
    for j in range(myindex[i]['timestamp'], 0, -1):
        if timestamps[myindex[i]['timestamp']] - timestamps[j] < 0.1:
            preCount += 1
        else:
            break
    attribute['prePackets'] = preCount

    attributes.append(attribute);

# write out
f = open('http_train.csv', 'w')
for i in range(0, index):
    mytemp = attributes[i]
    f.write(str(0) + ',' +  str(mytemp['otherRefer']) + ',' + str(mytemp['uri']) + ',' + str(mytemp['accept']) + ',' + str(mytemp['nextPackets']) + ',' + str(mytemp['prePackets']) + '\n')
f.close()
