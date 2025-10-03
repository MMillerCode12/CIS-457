from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53

dns_cache = {}

def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))

  # try to receive the packet, if it times out, send empty record

  try: 
    pkt, _ = udp_socket.recvfrom(8192)
  except:
    print("-> Query Timed Out <-")
    return {
      "ans": [],
      "auth": [],
      "add": []
    }
  
  buff = DNSBuffer(pkt)
  
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """

  # setup dictionary to store record information and return it

  return_info = {
    "ans": [],
    "auth": [],
    "add": []
  }

  header = DNSHeader.parse(buff)
  if q.header.id != header.id:
    print("Unmatched transaction")
    return
  if header.rcode != RCODE.NOERROR:
    print("Query failed")
    return

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    
  # Parse the answer section #3
  for k in range(header.a):
    a = RR.parse(buff)
    
    return_info["ans"].append(a)
      
  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)

    return_info["auth"].append(auth)
    
      
  # Parse the additional section #5
  for k in range(header.ar):
    adr = RR.parse(buff)

    if adr.rtype != QTYPE.AAAA:
      return_info["add"].append(adr)


  return return_info

def resolver(socket, domain_name, server_name, cc):

  # if invalid server name, return None

  if server_name is None:
    return None

  # set up the query server, domain being resolved, and amount of calls on the domain variables

  current_server = server_name
  current_domain = domain_name
  call_count = cc

  # if the domain being queried is in cache, fetch it from cache and return it

  if domain_name in dns_cache:
    print("Got from cache")
    return dns_cache[domain_name][0]

  split_domain_name = domain_name.split(".")

  for i in range(len(split_domain_name)):
    domain_cache_check = '.'.join(split_domain_name[i:])
    
  if domain_cache_check in dns_cache:
      print("new server from cache")
      current_server = dns_cache[domain_cache_check]

  

  while True:

    # increment call count and set up current name server and new query server variables

    call_count += 1
    current_ns = None
    new_server = None

    # if it's the first 2 calls, send an NS query. if it's the third call or later, send an A query

    if call_count > 2:
      record = get_dns_record(socket, current_domain, current_server, "A")
    else:
      record = get_dns_record(socket, current_domain, current_server, "NS")

    # If Query Timed out, return None

    if record is not None:
      if len(record["add"]) == 0 and len(record["auth"]) == 0 and len(record["ans"]) == 0:
        return None

    # set up alias variable for use later in the function

    is_cname = False

    if record is None:
      return None

    # first check for any NS records in authortitative and additional record sections

    if len(record["auth"]) > 0:

      # First, loop through the auth records

      for k in range(len(record["auth"])):

        # If there is an NS record in the authoritative section, try that as our next server to query

        if record["auth"][k].rtype == QTYPE.NS:
          current_ns = str(record["auth"][k].rdata)

          # it's important to note that current_ns will be the domain name of the new server and not the IP address

          if call_count == 1:
            print(f"Consulting Root Server: {current_ns}")
          elif call_count == 2: 
            print(f"Consulting TLD Server: {current_ns}")
          else:
            print(f"Consulting Auth Server: {current_ns}")

          break
      
      # Loop through the additional records to find a matching IP address for the domain name

      for k in range(len(record["add"])):

        # If the additional record's rname is the same as current_ns, there is a domain match.

        if str(record["add"][k].rname) == current_ns:
          
          # If the domain name is in cache and the IP address isn't listed for that domain,
          # add that IP address to the list for that domain.
          # If there is no cache entry for that domain, create one and add the IP address

          if current_ns in dns_cache:
            if str(record["add"][k].rdata) not in dns_cache[current_ns]:
              dns_cache[current_ns].append(str(record["add"][k].rdata))
          else:
            dns_cache[current_ns] = [str(record["add"][k].rdata)]

          # set the new server variable to the IP address of the name server domain

          new_server = str(record["add"][k].rdata)
          break

    # Next, if there are any answer records, we'll loop through those to get either an answer or alias

    if len(record["ans"]) > 0:

      for k in range(len(record["ans"])):

        # Check if the answer record is actually an answer

        if record["ans"][k].rtype == QTYPE.A:

          # If the domain name is in cache and the IP address isn't listed for that domain,
          # add that IP address to the list for that domain.
          # If there is no cache entry for that domain, create one and add the IP address

          if domain_name in dns_cache:
            if str(record["ans"][k].rdata) not in dns_cache[domain_name]:
              dns_cache[domain_name].append(str(record["ans"][k].rdata))
          else:
            dns_cache[domain_name] = [str(record["ans"][k].rdata)]

          # Since we have an answer for the domain we're querying about,
          # we just return that IP address

          return str(record["ans"][k].rdata)
        
        # Check if the answer record is an alias

        if record["ans"][k].rtype == QTYPE.CNAME:

          # Reset all of the variables and start the loop over again
          # As if the original domain was the alias

          current_domain = str(record["ans"][k].rdata)

          print(f"-> Alias Domain Name: {current_domain}")

          current_server = ROOT_SERVER
          is_cname = True
          call_count = 0
          break
    
    # If there is an alias, skip through the loop and start again

    if is_cname:
      continue
    
    # If the domain name for the next server to query never got resolved,
    # do a recursive call to the resolve function to get the IP address for
    # the next server

    if new_server is None:
      new_server = resolver(socket, current_ns, ROOT_SERVER, 0)

    # Set the server to query as our new name server we have found
    # and start the loop over again

    current_server = new_server
    

if __name__ == '__main__':
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)

  while True:
    domain_name = input("Enter a domain name or .exit > ")

    if domain_name == '.exit':
      break
    elif domain_name == '.list':
      
      cache_count = 1
      
      for i in dns_cache:
        print(f"{cache_count}. {i}: {dns_cache[i]}")
        cache_count += 1

      continue
    elif domain_name == '.clear':
      print("Cache has been cleared.")
      dns_cache = {}
      continue
    elif len(domain_name) > 7:
      if domain_name[:7] == '.remove':

        split_str = domain_name.split()
        count = 1

        for i in dns_cache:
          if count == int(split_str[1]):
            del dns_cache[i]
            break

          count += 1

        continue

    resolved_ip = resolver(sock, domain_name, ROOT_SERVER, 0)

    if resolved_ip is None:
      print("That domain doesn't exist.")
      continue

    print(f"IP Address Obtained From Auth Server: {resolved_ip}")
  
  sock.close()