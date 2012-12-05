import re

#take packet. return P
def match(packet):
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

print match("227-lskjdf \n  232 asdfsdf \n227 msg (1,2,3,4,5,6)")
print
print match("228-stuff \n 229 felkjsf \n229 msf (|||12345|).")
print
print match("sdfs")
print
print match("227 msg (1,2,3,4,5,6)")
