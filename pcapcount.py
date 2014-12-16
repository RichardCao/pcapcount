import pcap
import dpkt
import multiprocessing
import time
import copy
import traceback
import atexit
import signal
import sys

class sendData(multiprocessing.Process):

    def __init__(self, dict_f,  interval, outfilepre, myblock):
        multiprocessing.Process.__init__(self)
        self.li_flow_count = dict_f
        self.interval = interval
        self.outfilepre = outfilepre
	self.myblock = myblock
	self.threadalive = True

    def run(self):
        while self.threadalive:
	    self.myblock.acquire()
	    count_length = len(self.li_flow_count)
	    self.myblock.release()
            if count_length > 1: 
		self.myblock.acquire()
		# copy works as well as deepcopy since int, string(for pktcountslot) and tuple int are unchangable
		flow_count_f = self.li_flow_count.copy()
		self.li_flow_count.clear()
		self.li_flow_count["pktcountslot"] = 0
		self.myblock.release()
		count_slot = flow_count_f["pktcountslot"]
		del flow_count_f["pktcountslot"]
		''' replace the following part with curl request'''
                outfile = "./" + self.outfilepre + time.strftime("%Y-%m-%d-%H-%M-%S")
		out = open(outfile, 'w')
                out.write("# of flows = " + str(len(flow_count_f)) + "\n# of packets = " + str(count_slot) + "\n")
                sorted_flow_count = sorted(flow_count_f.iteritems(), key = lambda asd:asd[1], reverse = True)
                for obj in sorted_flow_count:
                    out.write(obj[0][0] + " " + obj[0][1] + " " + str(obj[1]) +  "\n")
                out.write("\n")                
                out.close()
		''' '''
            time.sleep(self.interval)
    def stop(self):
	self.threadalive = False

class listenInterface(multiprocessing.Process):

    def __init__(self, interface, dict_f, myblock):
        multiprocessing.Process.__init__(self)
        self.interface = interface
        self.packetscount = 0
	self.packetscountslot = 0
        self.flow_count = dict_f
        self.pc = None
	self.myblock = myblock
	self.threadalive = True
    
    def run(self):
        self.startListen()

    def startListen(self):
	print "start capturing %s . . ." % self.interface
        try:
            self.pc = pcap.pcap(self.interface)
	except Exception as ex:
            print "\n[ERROR]Failed to listen the interface!"
	    traceback.print_exc()
            return
	for ts, pkt in self.pc:
	    if not self.threadalive:
		return
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
                src= "256.256.256.256"
            if hasattr(p.data, "dst"):
                dst='%d.%d.%d.%d' % tuple(map(ord, list(p.data.dst)))
            else:
                dst= "256.256.256.256"
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
            self.flow_count["pktcountslot"] = self.flow_count["pktcountslot"] + 1
	    #print "length = %d" % len(self.flow_count)
	    self.myblock.release()

    def stop(self):
	self.threadalive = False

class listenController(multiprocessing.Process):
    def init(self):
	multiprocessing.Process.__init__(self)
	self.listeninstance = None
	self.sendinstance = None
    def run(self):
	try:
	    mgr = multiprocessing.Manager()
	    dict_f = mgr.dict()
	    dict_f["pktcountslot"] = 0
	    myblock = multiprocessing.RLock()
	    self.listeninstance = listenInterface("eth1", dict_f, myblock)
            self.listeninstance.start()
            self.sendinstance = sendData(dict_f, 3, "output", myblock)
	    self.sendinstance.start()
	    self.listeninstance.join()
	    self.sendinstance.join()
	    self.listeninstance.stop()
	    self.sendinstance.stop()
	except Exception, ex:
	    print "failed"
	    print ex
	    return
    def killall(self):
	self.listeninstance.terminate()
	self.sendinstance.terminate()
	
def _exit_clean():
    listen.killall()
    listen.terminate()

global listen
if __name__ == "__main__":
    global listen
    signal.signal(signal.SIGINT, _exit_clean)
    signal.signal(signal.SIGTERM, _exit_clean)
    try:
	listen = listenController()
	listen.start()
    	atexit.register(_exit_clean)
    	listen.join()
    except:
	self.terminate()
	listen.terminate() 
