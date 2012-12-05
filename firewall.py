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

    self.debug_print("Firewall initialized.")
    # k,v = conection,timer
    self.white_list = []
    self.timers = {}

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    port = flow.dstport
    dst = str(flow.dst)
    connection = (dst, port)
    packet_info = "[" + str(flow.src) + ":" + str(flow.srcport) + " to " + str(flow.dst) + ":" + str(flow.dstport) + "]"
    self.debug_print("Connection is " + str(connection) + " whitelist is " + str(self.white_list))  

    #ftp
    if port == 21:
      self.debug_print("DEFERED: FTP" + packet_info )
      event.action.monitor_forward = True
      event.action.monitor_backward = True

    #general
    elif port < 1024:
      self.debug_print("FORWARDED: " + packet_info )
      event.action.forward = True

    #whitelist
    elif connection in self.white_list:
      self.debug_print("DEFERED: WHITELIST" + packet_info)
      if connection not in self.timers:
        self.timers[connection] = Timer(10, self.timeOut, args = [connection])
      else:
        self.debug_print("Error" + packet_info)

      event.action.monitor_forward = True
      event.action.monitor_backward = True

    #we hate it
    else:
      self.debug_print("DENIED: " + packet_info) 
      event.action.deny = True

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    #NOTHING COMES HERE!!!!!!

  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """

    def match(packet):
    #print packet
      self.debug_print("packet is" + str(packet))

      if re.match(r"^227",packet):
        lastline = packet.splitlines()[-1]
        code = lastline.split(" ")[-1] 
        values = code.split(",")
        if len(values) != 6:
            return None
        self.debug_print("values is " + str(values))
        port = int(values [4])*256 + int(values[5].split(")")[0])
        h0 = values[0].split("(")[1]
        h1 = values[1]
        h2 = values[2]
        h3 = values[3]
        ip = h0 + "." + h1 + "." + h2 + "." + h3
        return ip, port
      elif re.match(r"^229",packet):
        lastline = packet.splitlines()[-1]
        code = lastline.split(" ")[-1] 
        value = code.split("(|||")[1]
        self.debug_print("value is " + value)
        port = int(value.split("|)")[0])
        #TODO: where do we get the ip for for this case
        return None, port
      else:
        return None

    if reverse:
      port =  packet.payload.payload.srcport
      dstip = str(packet.payload.srcip)
    else:
      return

    
    connection = (port,dstip)
    #data packet, reset time if we've seen it before
    if connection in self.timers:
      self.timers[connection].cancel()
      self.timers[connection] = Timer(10, self.timeOut, args = [connection])
    else:
      data = packet.payload.payload.payload
      connection  = match(str(data))
      #command packet, reply to passive
      if connection:
        if not connection[0]:
          connection = (dstip, connection[1])
        self.white_list.append(connection)


  def timeOut(self, connection):
    self.debug_print("REMOVING SOME PORT FROM WHITELIST")
    self.white_list.remove(connection)
    del self.timers[connection]

  def debug_print(self, s):
    if True:
      log.debug(s)
