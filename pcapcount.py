import pcap
import dpkt
import threading
import time


class sendData(threading.Thread):

    def __init__(self, listeninstance, interval, outfilepre):
        threading.Thread.__init__(self)
        self.listeninstance = listeninstance
        self.interval = interval
        self.outfilepre = outfilepre

    def run(self):
        while True:
            print listeninstance
            print len(listeninstance.flow_count)
            if(listeninstance != None and len(listeninstance.flow_count) > 0): 
                print "bbb"
                outfile = self.outfilepre + time.strftime("%Y-%m-%d-%H-%M-%S")
                print outfile
                print self.listeninstance.flow_count
                out = open(outfile, 'w')
                out.write(str(listeninstance.packetscount))
                out.write(str( listeninstance.pc.stats()))
                out.write("\n")
                sorted_flow_count = sorted(listeninstance.flow_count.iteritems(), key = lambda asd:asd[1], reverse = True)
                for obj in sorted_flow_count:
                    out.write(obj[0] + " " + str(obj[1]) + "\n")
                out.write("\n")                
                out.close()
            time.sleep(self.interval)

class listenInterface(threading.Thread):

    def __init__(self, interface):
        threading.Thread.__init__(self)
        self.interface = interface
        self.packetscount = 0
        self.flow_count = {}
        self.pc = None
    
    def run(self):
        self.startListen()

    def startListen(self):
        try:
            self.pc = pcap.pcap(self.interface)
        except:
           print "error"
        for ts, pkt in self.pc:
            self.packetscount = self.packetscount + 1
            print self.packetscount
            p = dpkt.ethernet.Ethernet(pkt)
            if p == None:
                continue
            if p.data == None:
                continue
            if hasattr(p.data, "src"):
                src ='%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
            else: 
                src= "........"
            if hasattr(p.data, "dst"):
                dst='%d.%d.%d.%d' % tuple(map(ord, list(p.data.dst)))
            else:
                dst= "........"
            if hasattr(p.data, "data"):
                if hasattr(p.data.data, "sport"):
                    sport = p.data.data.sport
                else:
                    sport= -1
                if hasattr(p.data.data, "dport"):
                    dport = p.data.data.dport
                else:
                    dport= -1
            if self.flow_count.has_key(src + "-" + dst):
                self.flow_count[src + "-" + dst] = self.flow_count[src + "-" + dst] + 1;
            else:
                self.flow_count[src + "-" + dst] = 1;
            print "len=%d" % len(self.flow_count)

if __name__ == "__main__":
    block = threading.RLock()
    print 1
    listeninstance = listenInterface("eth1")
    print 2
    sendinstance = sendData(listeninstance, 1, "output")
    print 3
    sendinstance.start()
    print 4
    listeninstance.start()
    print 5
