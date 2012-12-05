import re

#take packet. return P
def match1(packet):
  print packet
  if re.match(r"^227",packet):
    lastline = packet.splitlines()[-1]
    code = lastline.split(" ")[-1] 
    values = code.split(",")
    port = int(values [4])*256 + int(values[5].split(")")[0])
    return port
  elif re.match(r"^229",packet):
    lastline = packet.splitlines()[-1]
    code = lastline.split(" ")[-1] 
    value = code.split("(|||")[1]
    port = int(value.split("|)")[0])
    return port
  else:
    return None

def match(packet):
  if re.match(r"^227",packet):
    lastline = packet.splitlines()[-1]
    if not re.match(r"^227", lastline):
      return None
    code = lastline.split(" ")[-1] 
    if re.match(r"\(.*\)\.?", code):
      code = code.strip(".").strip("(").strip(")")
    values = code.split(",")
    if len(values) != 6:
      return None
    for x in values:
      if not x.isdigit():
        return None
    for ip in values[:4]:
      if int(ip) > 256:
        return None
    for p in values[4:]:
      if int(p) > 65536:
        return None
    port = int(values[4])*256 + int(values[5])
    ip = values[0] + "." + values[1] + "." + values[2] + "." + values[3]
    return ip, port
  elif re.match(r"^229",packet):
    lastline = packet.splitlines()[-1]
    if not re.match(r"^229", lastline):
      return None
    code = lastline.split(" ")[-1]
    if not re.match(r"\(\|\|\|.*\|\)", code):
      return None
    port = code.strip("(").strip(")").strip("|")
    if not port.isdigit():
      return None
    if int(port) > 65525:
      return None
    return None, int(port)
  else:
    return None



print match("227-lskjdf \n  232 asdfsdf \n227 msg (1,2,3,4,5,6).")
print
print match("229-stuff \n 200 felkjsf \n229 msf (|||12345|)")
print
print match("sdfs")
print
print match("227 msg (1,2,3,4,5,6)")
print
print match("229-stuff \n 200 felkjsf \n229 msf (||2345|)")
print
print match("229-stuff \n 200 felkjsf \n229 msf (||||)")
print
print match("229-stuff \n 200 felkjsf \n229 msf (|||12s345|)")
print
print match("229-stuff \n 200 felkjsf \n229 msf (|||12345|v)")
print
print match("227-lskjdf \n  232 asdfsdf \n227 msg (1,2,3,4,5).")
print
print match("227-lskjdf \n  232 asdfsdf \n227 msg (1,2,3,4,5,23423434).")
print
print match("227-lskjdf \n  232 asdfsdf \n227 msg (1,500,3,4,5,6).")
print
print match("227-lskjdf \n  232 asdfsdf \n227 msg (1,a2,3,4,5,6).")
print
print match("227-lskjdf \n  232 asdfsdf \n227 msg (1,2,3,4,5,6.")
print

