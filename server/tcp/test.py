#!/usr/bin/python

# A simple example of how to use pcapy. This needs to be run as root.

import datetime
import gflags
import pcapy
import sys
import urllib2, socket, impacket,impacket.ImpactDecoder

FLAGS = gflags.FLAGS
gflags.DEFINE_string('i', 'em1',
                     'The name of the interface to monitor')


socket.setdefaulttimeout(5)
def main(argv):
  # Parse flags
  try:
    argv = FLAGS(argv)
  except gflags.FlagsError, e:
    print FLAGS

  print 'Opening %s' % FLAGS.i

  # Arguments here are:
  #   device
  #   snaplen (maximum number of bytes to capture _per_packet_)
  #   promiscious mode (1 for true)
  #   timeout (in milliseconds)
  cap = pcapy.open_live(FLAGS.i, 100, 1, 0)
  cap.setfilter("port 20002")
  # Read packets -- header contains information about the data from pcap,
  # payload is the actual packet as a string
  (header, payload) = cap.next()
  while header:
    print header
    print ('%s: captured %d bytes, truncated to %d bytes'
           %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
    print dir(header), dir(payload)
    print payload
    decoder = impacket.ImpactDecoder.EthDecoder()
    p = decoder.decode(payload)
    print p.child().child().get_th_dport()
    print p.child().child().get_th_sport()
    print p.child().get_ip_src()
    (header, payload) = cap.next()
    break
  return p.child().get_ip_src(), p.child().child().get_th_sport()


if __name__ == "__main__":
    ip, port = main(sys.argv)
    try:
      a = socket.create_connection((ip, port), 5,  ("", 20002))
      a.send("get /index.html\n")
      print a.recv(65000)
      #a = urllib2.urlopen("http://98.206.139.114:20002")
      #print a.getcode()
      #print a.read()
    except urllib2.URLError:
      print "error :("
