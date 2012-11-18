from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
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
    self.banned_ports = open('/root/pox/ext/banned-ports.txt').read().splitlines()
    self.banned_domains = open('/root/pox/ext/banned-domains.txt').read().splitlines()


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
    event.action.forward = True
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    event.action.forward = True
