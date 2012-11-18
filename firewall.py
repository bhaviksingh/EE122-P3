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

    self.monitored_counts = {}
    self.currently_timed = {}
    self.lastTexts = {}
    self.maxLengths = {}

    for line in monitored_list:
      ip, text = line.strip().split(":")

      if ip not in self.monitored_counts:
        self.monitored_counts[ip] = {}
        self.monitored_counts[ip][text] = 0
        self.maxLengths[ip] = len(text)     
        self.lastTexts[ip] = ("", {text: 0})
      else:
        self.monitored_counts[ip][text] = 0
        self.maxLengths[ip] = max(len(text), self.maxLengths[ip])
        self.lastTexts[ip][1][text] = 0





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

    if ip in self.monitored_counts:
      #reinitialize the content to make it the last times + this times

      content = self.lastTexts[ip][0] + str(packet.payload.payload.payload)
      subset = str(packet.payload.payload.payload)[-self.maxLengths[ip]:]
      subsetCount = {}
      #lets go through each string now, and adjust weights
      for monitored in self.monitored_counts[ip]:
        count  = content.count(monitored) - self.lastTexts[ip][1][monitored]
        self.monitored_counts[ip][monitored] += count
        if monitored in subsetCount:
          subsetCount[monitored] += subset.count(monitored)
        else: 
          subsetCount[monitored] = subset.count(monitored)

      #make the last times the thing it needs to be for next time
      self.lastTexts[ip] = (subset, subsetCount)

      if ip in self.currently_timed:
        self.currently_timed[ip].cancel()
      self.currently_timed[ip] = Timer(30, self.writeCounts, args = (ip, port))


  def writeCounts(self, ip, port):
    counts = open('ext/counts.txt', 'a')
    for monitored in self.monitored_counts[ip]:
      line = str(ip) + ',' + str(port) + ',' + str(monitored) + ',' + str(self.monitored_counts[ip][monitored]) + '\n'
      counts.write(line)
      counts.flush()
    counts.close()
    for monitored in self.monitored_counts[ip]:
      self.monitored_counts[ip][monitored] = 0
