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
    # k,v = conection,timer
    self.white_list = {}

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    port = flow.dstport

    if port == 21:
      log.debug("CONNECTIONIN: FTP [" + str(flow.src) + ":" + str(flow.srcport) + " to " + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.defer = True
    elif port < 1024:
      log.debug("CONNECTIONIN: " + str(flow.src) + ":" + str(flow.srcport) + " to " + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.forward = True
    elif port in self.white_list:
      log.debug("WHITELIST: " + str(flow.src) + ":" + str(flow.srcport) + " to " + str(flow.dst) + ":" + str(flow.dstport) + "]")
      event.action.forward = True
    else:
      log.debug("CONNECTIONIN: DENIED [" + str(flow.src) + ":" + str(flow.srcport) + " to " + str(flow.dst) + ":" + str(flow.dstport) + "]" ) 
      event.action.deny = True

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    log.debug("Defer connection called")

    event.action.monitor_forward = True
    event.action.monitor_backward = True


  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    if not reverse:
      port =  packet.payload.payload.dstport
    else:
      return

    data = packet.payload.payload.payload

    log.debug("monitor called to:" + str(port) + " data was " + str(data))
    if "227" in data:
      log.debug("PASV PACKET")
    elif "229" in data:
      log.deug("EPSV PACKET")


