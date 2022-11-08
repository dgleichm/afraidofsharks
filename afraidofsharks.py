#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import pyshark
import argparse

#pip install pyshark


### HELPER FUNCTIONS (IF NECESSARY) ###
parser = argparse.ArgumentParser()
parser.add_argument('filename')
parser.add_argument('--network', help = 'Network summary containing protocol, source address, source port, destination address, destination port', action='store_const', const = 'network')
parser.add_argument('--smtp', help = 'Tells packet number of where interesting smtp information is such as emails.', action='store_const', const = 'smtp')
parser.add_argument('--http', help = 'Gives http type and gives website visited with url.', action='store_const', const = 'http')

args = parser.parse_args()

def network(capture):
 
  try:
    protocol = capture.transport_layer
    source_address = capture.ip.src
    source_port = capture[capture.transport_layer].srcport
    destination_address = capture.ip.dst
    destination_port = capture[capture.transport_layer].dstport
    return (f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}')
  except AttributeError as e:
    pass

def sort(capture):

  conversations = []
  NoDuplicates = []
  for packet in capture:
    results = network(packet)
    if results != None:
      conversations.append(results)
  for eachWord in conversations:
    if eachWord not in NoDuplicates:
      NoDuplicates.append(eachWord)
      NoDuplicates = sorted(NoDuplicates)
    
    
    # this sorts the conversations by protocol 
    # TCP and UDP
  # for item in sorted(NoDuplicates):
  return(NoDuplicates)
  

def smtp(capture):

  smtp_list = []
  for info in capture:
    if 'smtp' in info:
      if info.smtp.get_field_value("data_fragment"):
        smtp_info = info.smtp.get_field_value("data_fragment")
        output = ('interesting packet: ' + smtp_info)
        smtp_list.append(output)
  return (smtp_list) 


def http(capture):

  http_list = []
  for info in capture:
    if 'http' in info:
      if info.http.get_field_value("request.method") is not None:
        frame = info.frame_info.get_field_value("number")
        method = info.http.get_field_value("request.method")
        host = info.http.get_field_value("http.host")
        uri = info.http.get_field_value("request.uri")
        output = (str(frame) + ": " + str(method) + ": "  + str(host) + ': ' + str(uri))
        http_list.append(output)
     
  return http_list

def allinfo(capture):
  if args.network:
      output= sort(capture)
      print("="*50)
      print(*output, sep = "\n")
      print('-'*50)
  elif args.smtp:
      output = smtp(capture)
      if output != []:
        print('='*20)
        print(*output, sep = "\n")
        print('-'*20)
      elif output == []:
        print('No smtp traffic found.')
  elif args.http:
      output = http(capture)
      if output != []:
        print('='*50)
        print(*output, sep = "\n")
        print('-'*50)
      elif output == []:
        print('No http traffic found.')
  else:
    output = sort(capture)
    output2 = smtp(capture)
    output3 = http(capture)
    print('='*50)
    print('Network Traffic:')
    print('-'*50)
    print(*output, sep = "\n")
    print('-'*50)
    if output2 != []:
      print('SMTP Traffic:')
      print('-'*50)
      print(*output2, sep = "\n")
      print('-'*50)
    elif output2 == []:
      print('SMTP Traffic:')
      print('No smtp traffic found.')
      print('-'*50)
    if output3 != []:
      print("HTTP Traffic:")
      print('-'*50)
      print(*output3, sep = "\n")
      print("="*50)
    elif output3 == []:
      print("HTTP Traffic:")
      print('-'*50)
      print('No http traffic found.')
      print('='*50)
    
      
#new function for if not statement 



### MAIN FUNCTION ###
def main():
  packet = sys.argv[1]
  capture = pyshark.FileCapture(packet)
  if args.network:
    network(capture)
    sort(capture)
    allinfo(capture)
  elif args.smtp:
    smtp(capture)
    allinfo(capture)
  elif args.http:
    http(capture)
    allinfo(capture)
  else:
    network(capture)
    sort(capture)
    smtp(capture)
    http(capture)
    allinfo(capture)
  #logic check


### DUNDER CHECK ###
if __name__ == "__main__":
  main()


