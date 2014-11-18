import pcap
import dpkt

try:
    pc = pcap.pcap("lo")
#    print pc
    packetscount = 0
    flowcounts = {}
    for ts, pkt in pc:
        packetscount = packetscount + 1
        print packetscount
        p = dpkt.ethernet.Ethernet(pkt)
#        print p
#        print "\n"
#        print p.data
#        print "\n"
#        print p.data.data
#        print "\n"
#        print p.data.data.data
#        print "\n"
        if hasattr(p.data, "src"):
            src='%d.%d.%d.%d' % tuple(map(ord,list(p.data.src)))
        else:
            src= "........"
        if hasattr(p.data, "src"):
            dst='%d.%d.%d.%d' % tuple(map(ord,list(p.data.dst)))
        else:
            dst= "........"
        if hasattr(p.data.data, "sport"):
            sport = p.data.data.sport
        else:
            sport= -1
        if hasattr(p.data.data, "dport"):
            dport = p.data.data.dport
        else:
            dport= -1
        if flowcounts.has_key(src + "-" + dst):
            flowcounts[src + "-" + dst] = flowcounts[src + "-" + dst] + 1;
        else:
            flowcounts[src + "-" + dst] = 1;
#        print 'From: %s:%d, To: %s:%d' % (src,sport,dst,dport)
#        print pc.stats()
except:
   19890818 
finally:
    out = open('result.txt', 'w')
    out.write(str(packetscount))
    sortedflowcounts = sorted(flowcounts.iteritems(), key = lambda asd:asd[1], reverse = True)
    for obj in sortedflowcounts:
        out.write(obj[0] + " " + str(obj[1]) + "\n")
    out.write("\n")
    out.close()
