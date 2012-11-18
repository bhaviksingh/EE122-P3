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

    self.port_count = {}
    self.lastTexts = {}
    self.lastCounts = {}
    self.currently_timed = {}

    for line in monitored_list:
      ip, text = line.strip().split(":")

      if ip not in self.monitored_strings:
        self.monitored_strings[ip] = {}
        self.monitored_strings[ip][text] = 0
        self.maxLengths[ip] = len(text)   

        #port specific  
        self.lastTexts[ip] = {}
        self.lastCounts[ip] = {}
        self.port_count[ip] = {}

      else:
        self.monitored_strings[ip][text] = 0
        self.maxLengths[ip] = max(len(text), self.maxLengths[ip])

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """

    if str(flow.dstport) in self.banned_ports:
      event.action.deny = True
      log.debug("Denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    else: 
      event.action.defer = True
      log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )

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
    ip = str(packet.payload.dstip)
    port = str(packet.payload.payload.dstport)

    if reverse:
      ip = str(packet.payload.srcip)
      port = str(packet.payload.payload.srcport)

    if ip in self.monitored_strings:

      if port in self.lastTexts[ip]:
        content = self.lastTexts[ip][port] + str(packet.payload.payload.payload)
      else: 
        #this is the first time we are seeing this port,ip, so initialize everything for lastTexts and portCount
        self.lastTexts[ip][port] = ""
        self.lastCounts[ip][port] = {}
        self.port_count[ip][port] = {}
        content = str(packet.payload.payload.payload)

        for monitored in self.monitored_strings[ip]:
          self.lastCounts[ip][port][monitored] = 0
          self.port_count[ip][port][monitored] = 0

      subset = str(packet.payload.payload.payload)[-self.maxLengths[ip]:]

      for monitored in self.monitored_strings[ip]:
        #get the actual count for this time
        count = content.count(monitored) - self.lastCounts[ip][port][monitored]
        self.port_count[ip][port][monitored] += count
        #set the subset count
        self.lastCounts[ip][port][monitored] = subset.count(monitored)

      self.lastTexts[ip][port] = subset

      if ip in self.currently_timed:
        if port in self.currently_timed[ip]:
          self.currently_timed[ip][port].cancel()
        else:
          self.currently_timed[ip] = {port: Timer(30, self.writeCounts, args = (ip, port))}
      else:
        self.currently_timed[ip] = {}
        self.currently_timed[ip][port] =  Timer(30, self.writeCounts, args = (ip, port))

  def writeCounts(self, ip, port):
    counts = open('ext/counts.txt', 'a')
    for monitored in self.port_count[ip][port]:
      line = str(ip) + ',' + str(port) + ',' + str(monitored) + ',' + str(self.port_count[ip][port][monitored]) + '\n'
      counts.write(line)
      counts.flush()
    counts.close()
    #reset our count for the connection
    for monitored in self.port_count[ip][port]:
      self.port_count[ip][port][monitored] = 0

