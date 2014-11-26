import pcap
import dpkt
import threading
import time
import copy
import sys


class sendData(threading.Thread):

    def __init__(self, listeninstance, interval, outfilepre, myblock):
        threading.Thread.__init__(self)
        self.listeninstance = listeninstance
        self.interval = interval
        self.outfilepre = outfilepre
	self.myblock = myblock

    def run(self):
        while True:
	    #use len(self.listeninstance.flow_count) instead of self.listeninstance.packetscountslot for safe access
            if(self.listeninstance != None and len(self.listeninstance.flow_count) > 0): 
		self.myblock.acquire()
		# copy works as well as deepcopy since tuple and int are unchangable
		flow_count_f = self.listeninstance.flow_count.copy()
		self.listeninstance.flow_count.clear()
		packetscountslot_f = self.listeninstance.packetscountslot
                self.listeninstance.packetscountslot = 0
		self.myblock.release()
                outfile = "./" + self.outfilepre + time.strftime("%Y-%m-%d-%H-%M-%S")
                out = open(outfile, 'w')
                out.write("# of flows = " + str(len(flow_count_f)) + "\n# of packets = " + str(packetscountslot_f) + "\n")
                sorted_flow_count = sorted(flow_count_f.iteritems(), key = lambda asd:asd[1], reverse = True)
                for obj in sorted_flow_count:
                    out.write(obj[0][0] + " " + obj[0][1] + " " + str(obj[1]) +  "\n")
                out.write("\n")                
                out.close()
            time.sleep(self.interval)

class listenInterface(threading.Thread):

    def __init__(self, interface, myblock):
        threading.Thread.__init__(self)
        self.interface = interface
        self.packetscount = 0
	self.packetscountslot = 0
        self.flow_count = {}
        self.pc = None
	self.myblock = myblock
    
    def run(self):
        self.startListen()

    def startListen(self):
        try:
            self.pc = pcap.pcap(self.interface)
        except:
           print "error"
        for ts, pkt in self.pc:
            self.packetscount = self.packetscount + 1
	    print "\rpackets captured = %d" % self.packetscount,
    	    sys.stdout.flush()
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
	    self.myblock.acquire()
            if self.flow_count.has_key((src, dst)):
                self.flow_count[(src, dst)] = self.flow_count[(src, dst)] + 1;
            else:
                self.flow_count[(src, dst)] = 1;
            self.packetscountslot = self.packetscountslot + 1
	    self.myblock.release()

if __name__ == "__main__":
    myblock = threading.RLock()
    listeninstance = listenInterface("eth1", myblock)
    sendinstance = sendData(listeninstance, 2, "output", myblock)
    sendinstance.start()
    listeninstance.start()
