from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.packet import *
from pox.lib.recoco.recoco import Timer
import re

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  
  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """

    log.debug("Firewall initialized.")
    self.banned_ports = open('ext/banned-ports.txt').read().splitlines()
    self.banned_domains = open('ext/banned-domains.txt').read().splitlines()
    monitored_list = open('ext/monitored-strings.txt').read().splitlines()

    self.monitored_strings = {}
    self.maxLengths = {}

    # port specific items
    self.currently_timed = {}
    self.port_count = {}
    self.lastTexts = {}


    for line in monitored_list:
      ip, text = line.strip().split(":")

      if ip not in self.monitored_strings:
        self.monitored_strings[ip] = [text]
        self.maxLengths[ip] = len(text)   

      else:
        self.monitored_strings[ip].append(text)
        self.maxLengths[ip] = max(len(text), self.maxLengths[ip])

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    if str(flow.dstport) in self.banned_ports:
      event.action.deny = True
      log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + " to " + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    else: 
      event.action.defer = True
      log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + " to " + str(flow.dst) + ":" + str(flow.dstport) + "]" )

    ip = flow.dstport
    if ip in monitored_strings:
      
      connection = (flow.src, flow.srcport, flow.dst, flow.dstport)
      self.port_count[connection] = {}
      self.lastTexts[connection] = {}
      
      for string in monitored_strings[ip]
        self.port_count[connection] = {string: [0, 0]}
        self.lastTexts[connection] = ["", ""]


  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """

    def check_banned_subdomain(url, banned):
      bannedlist = re.split('\.',banned)
      urllist = re.split('\.',url)
      path = re.split('\/', urllist[-1])
      urllist[-1] = path[0]
      path = re.split('\:', urllist[-1])
      urllist[-1] = path[0]
      if len(urllist) < len(bannedlist):
        return False
      for a,b in zip(reversed(bannedlist), reversed(urllist)):
          if a != b:
              return False
      return True

    header =  str(packet.payload.payload.payload)
    banned = False
    if 'Host: ' in header: 
        header = header.splitlines()
        for line in header:
            if 'Host: ' in line:
                hostname = line.split(" ")[line.index('Host: ' ) + 1] 
                break
        for domain in self.banned_domains:
            if check_banned_subdomain(hostname, domain): 
                log.debug('Hostname ' + str(hostname) + ' was banned because of ' + domain)
                banned = True
        if banned:
            event.action.deny = True
            return
    event.action.monitor_forward = True
    event.action.monitor_backward = True
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """

    if not reverse:
      ip = packet.payload.srcip
      connection = (packet.payload.srcip, packet.payload, srcport, packet.payload.dstip, packet.payload.dstport)
      index = 0
    else:
      ip = packet.payload.dstip
      connection = (packet.payload.dstip, packet.payload.dstport, packet.srcip, packet.srcport)
      index = 1

    print "Current connection is ", connection

    if ip in self.monitored_strings:

      content  = self.lastTexts[connection][index] + str(packet.payload.payload.payload)
      subset = str(packet.payload.payload.payload)[-self.maxLengths[ip]:]

      for string in self.port_count[connection]:
        count = content.count(string) - self.lastTexts[connection][index].count(string)

      for string in self.monitored_strings[ip]:
        count = content.count(string) - self.lastCounts[ip][port][reverse_id][string] 
        self.port_count[ip][port][reverse_id][string] += count
        self.lastCounts[ip][port][reverse_id][string] = subset.count(string)
        #print "adding count to ", ip, port, string, " count = ", count

      self.lastTexts[ip][port][reverse_id] = subset

      if (ip,port) in self.currently_timed:
        self.currently_timed[(ip, port)].cancel()
      self.currently_timed[(ip,port)] = Timer(30, self.writeCounts, args = (ip, port))

  
  def initPortData(self, ip, port):
    self.port_count[ip][port] = {0 : {}, 1: {}}
    self.lastCounts[ip][port] = {0 : {}, 1: {}}
    self.lastTexts[ip][port] = {0 : "", 1: ""}
    for i in range(2):
      for string in self.monitored_strings[ip]:
        self.port_count[ip][port][i][string] = 0
        self.lastCounts[ip][port][i][string] = 0


  def writeCounts(self, ip, port):
    print " WRITING TO FILE FOR IP, PORT", ip , " ", port
    print "Monitored strings is " , self.monitored_strings
    print "Port count for this ip,port ",  self.port_count[ip][port]
    print " "
    counts = open('ext/counts.txt', 'a')
    for string in self.monitored_strings[ip]:
      total = self.port_count[ip][port][0][string] + self.port_count[ip][port][1][string]
      line = str(ip) + ',' + str(port) + ',' + str(string) + ',' + str(total) + '\n'
      counts.write(line)
      counts.flush()
    counts.close()
    #reset our count for the connection
    self.initPortData(ip, port)




