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

  """
  PEOPLE WHO ARE READING MY CODE, THIS IS WTF IS GOING ON:
  ftp uses two different connections. the first is some port (on your system) n -> 21. this is the COMMAND flow of ftp (sends instructions back and forth)
  the second is some random port m -> some port p. m is usually n+1, p is always > 1024. this is the DATA flow of ftp (sends the actual data)

  now, you automatically allow all ports < 1024, so n -> 21 is always allowed. However if its going to 21 its ftp command so you need to monitor it (see why later)
  if the port have a whitelist of (ip, port) pairings. so when the FTP server at some ip wants to open a data flow (ie: m -> p) this (ip,p) should be on the whitelist already

  well how do you know what (ip,p) is? thats where the monitor comes in. 
  at some point in the COMMAND flow, the ip server will send you a packet of the form "227 message (ip, port)" or "229 message (||| port|)". 
  if you see this packet, this means ftp wants to open the data connection. 
  so you if its 227, you add the (ip, port) from the message, if its 229 you add the ip from which the packet came from  and port from message = (dstip, port)

  the server then has 10 seconds to actually start the m->p connection. if 10seconds go by, and a connection hasn't been received, remove the (ip,port) from whitelist. 
  if you get a connection before those 10 seconds, then remove the port from whitelist and cancel timer. then just allow all data packets to go through! (so forward that connection)

  THATS IT! read the code, the comments should show you whats happening
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
    self.lastPacket = {}

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
      self.debug_print("ALLOWED: WHITELIST" + packet_info)
      if connection not in self.timers:
        self.debug_print("ERROR: whitelisted packet doesnt have timer so it shouldnt go through" + packet_info)
      else:
        #cancel the timer because the connection started. remove  (ip,port) from whitelist
        self.debug_print("REMOVED: from whitelist " + str(connection)+ " whitelist is " + str(self.white_list))
        self.timers[connection].cancel() 
        self.white_list.remove(connection)

      event.action.forward = True

    #we hate it, it can fuck off
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
    #TODO: MAYBE THIS SHOULD BE REMOVED. sets port and ip
    if reverse:
      port =  packet.payload.payload.srcport
      dstip = str(packet.payload.srcip)
    else:
      return
    
    connection = (dstip, port)
    if connection not in self.lastPacket:
      self.lastPacket[connection] = ""

    #this command packet
    data = packet.payload.payload.payload
    nindex = data.rfind('\n') + 1
    
    if nindex == 0:
      self.lastPacket[connection] += data
      return 

    postn = data[nindex:]
    data = self.lastPacket[connection] + data[ : nindex]
    self.lastPacket[connection] = postn

    # self.debug_print("DATA IS " + str(data) + " last packet is " + self.lastPacket[connection], True)

    for line in data.splitlines():
      self.debug_print("DATA IS " + str(line))
      connection  = self.match(str(line)) 

      if connection: #is 229 or 227 (so not none) 
        
        if not connection[0]: #epsv (229)
          connection = (dstip, connection[1])
        self.debug_print("Adding to whitelist " + str(connection))
        self.white_list.append(connection) #add connection to whitelist
        if connection in self.timers: #this is just to fix bugs
          self.timers[connection].cancel()
        self.timers[connection] = Timer(10, self.timeOut, args = [connection]) #create a timer for this data connection, so it has 10 seconds to start
        self.debug_print("Timers is " + str(self.timers))

  
  def timeOut(self, connection):
    self.white_list.remove(connection)
    self.debug_print("REMOVED: from whitelist " + str(connection))
    del self.timers[connection]

  def debug_print(self, s, t = False):
    """
    This function is to make the switch between "print" and "log.debug" easier. 
    the s is the string, the t variable is to override the if statement in case we want to print just one or two messages
    """
    if False or t:
      print s

  #plz ignore this match function. its a mess and could be much cleaner
  def match(self, line):
    """
    match checks if packet is 229 or 227 and returns (ip, port) or none. for 229 it returns (none, port) because you get the ip from dstip
    """
    self.debug_print("MATCH Packet is " + line)
    #227
    if re.match(r"^227",line):
      if not re.match(r"^227", line):
        return None
      code = line.split(" ")[-1] 
      if re.match(r".*\(.*\)\.?$", code):
        code = code.split("(")[-1] 
        code = code.strip(".").strip("(").strip(")")
      values = code.split(",")
      if len(values) != 6:
        return None
      for x in values:
        if not x.isdigit():
          return None
      for ip in values[:4]:
        if int(ip) > 255:
          return None
      port = int(values[4])*256 + int(values[5])
      if int(port) > 65525:
        return None
      ip = values[0] + "." + values[1] + "." + values[2] + "." + values[3]
      return ip, port

    #229
    elif re.match(r"^229", line):
      if not re.match(r"^229", line):
        return None
      code = line.split(" ")[-1]
      if not re.match(r"\(\|\|\|.*\|\)\.?$", code):
        return None
      port = code.strip(".").strip("(").strip(")").strip("|")
      if not port.isdigit():
        return None
      if int(port) > 65525:
        return None
      self.debug_print("RETURNING PORT" + port)
      return None, int(port)
    else:
      return None


