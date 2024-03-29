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

  def initData(self,connection):
    #print "INITIALIZING PORTCOUNT FOR ", connection
    self.port_count[connection] = {}
    self.lastTexts[connection] = {}
    
    for string in self.monitored_strings[connection[2]]:
      self.port_count[connection][string] = [0, 0]
      self.lastTexts[connection][string] = ["", ""]

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

    ip = str(flow.dst)
    if ip in self.monitored_strings:
      connection = (str(flow.src), str(flow.srcport), str(flow.dst),  str(flow.dstport))
       
      if connection in self.currently_timed:
        self.currently_timed[connection].cancel()
        self.writeCounts(connection)

      self.initData(connection)

     
  

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
      ip = str(packet.payload.dstip)
      connection = (str(packet.payload.srcip), str(packet.payload.payload.srcport), str(packet.payload.dstip), str(packet.payload.payload.dstport))
      index = 0
    else:
      ip = str(packet.payload.srcip)
      connection = (str(packet.payload.dstip), str(packet.payload.payload.dstport), str(packet.payload.srcip), str(packet.payload.payload.srcport))
      index = 1

    #print "Current connection is ", connection

    if ip in self.monitored_strings:

      #print "IP IS IN MONITORED, DOING OTHER SHIT ", ip
      #print "port count at this point is ", self.port_count

      
      #print "NEW PACKET"
      for string in self.monitored_strings[ip]:
        
        substring = self.lastTexts[connection][string][index]
        content  = substring + str(packet.payload.payload.payload)

        #print "For ", string, " content is ", content, " lenght is ", len(content), " substring length was ", len(substring)
        
        count = content.count(string) 
        self.port_count[connection][string][index] += count
        
        if content.count(string) == 0:
          self.lastTexts[connection][string][index] = content[ -(len(string) - 1):]
        else:
          self.lastTexts[connection][string][index] = self.lastIndex(content,string)

      if connection in self.currently_timed:
        self.currently_timed[connection].cancel()
      self.currently_timed[connection] = Timer(30, self.writeCounts, args = [connection])

  def lastIndex(self, s, pattern):
    while(s.find(pattern) >= 0):
      s = s[s.find(pattern) + len(pattern):]
    return s

  def writeCounts(self, connection):
    #print " WRITING TO FILE FOR CONNECTION", connection
    counts = open('ext/counts.txt', 'a')
    # srcip = connection[0]
    # srcport = connection[1]
    dstip = connection[2]
    dstport = connection[3]

    #print "PORTCOUNT IS ", self.port_count

    for string in self.monitored_strings[connection[2]]:
      total = self.port_count[connection][string][0] + self.port_count[connection][string][1]
      line = str(dstip) + ',' + str(dstport) + ',' + str(string) + ',' + str(total) + '\n'
      #print "writing", line
      counts.write(line)
      counts.flush()
    counts.close()
    self.initData(connection)





