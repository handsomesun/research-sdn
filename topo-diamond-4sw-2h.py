'''
#!/usr/bin/env python

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm

if '__main__' == __name__:
    net = Mininet(controller=RemoteController)

    c0 = net.addController('c0')

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')

    net.addLink(s1, h1)
    net.addLink(s2, h2)

    net.addLink(s1, s3)
    net.addLink(s3, s2)
    net.addLink(s2, s4)
    net.addLink(s4, s1)
    

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])

    net.startTerms()

    CLI(net)

    net.stop()
'''
"""Diamond Topology

Two directly connected switches plus a host for each switch:
                  1 s3 2
                2/      \ 1 
        h1 --- s1 3      s2 --- h2
         1 --- 1 \ 1  2/ 2  3   1
                    s4

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class DTopo( Topo ):

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        #leftHost = self.addHost('h1', mac = "00:00:00:00:00:01")
        leftHost = self.addHost('h1')
        #rightHost = self.addHost('h2', mac = "00:00:00:00:00:02")
        rightHost = self.addHost('h2')

        leftSwitch = self.addSwitch('s1')
        rightSwitch = self.addSwitch('s2')
        topSwitch = self.addSwitch('s3')
        bottomSwitch = self.addSwitch('s4')

        # Add links
        #self.addLink( leftHost, leftSwitch, 0, 0)
        self.addLink( leftHost, leftSwitch, port1 = 1, port2 = 1)
        self.addLink( leftSwitch, topSwitch, port1 = 2, port2 = 1 )
        self.addLink( leftSwitch, bottomSwitch, port1 = 3, port2 = 1 )
        self.addLink( rightSwitch, topSwitch, port1 = 1, port2 = 2 )
        self.addLink( rightSwitch, bottomSwitch, port1 = 2, port2 = 2 )
        self.addLink( rightSwitch, rightHost, port1 = 3, port2 = 1 )

        #print ("h1 mac addr: %v", leftHost.MAC)
        #print ("h2 mac addr: %v", rightHost.MAC)
        # s1 - s4 dpid, port
        # h1, h2 mac address
        #print("s1 dpid: %s", leftSwitch.id)
        #print("s2 dpid: %s", rightSwitch.id)
        #print("s3 dpid: %s", topSwitch.id)
        #print("s4 dpid: %s", bottomSwitch.id)
        #print("h1 mac address: %s", h1.address)
        #print("h2 mac address: %s", h2.address)

topos = { 'dtopo': ( lambda: DTopo() ) }