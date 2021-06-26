
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import RemoteController
class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, s1)
        self.addLink(s5, h2)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s5)
        self.addLink(s1, s4)
        self.addLink(s4, s5)

def run():
    topo = MyTopo()
    net = Mininet(topo = topo, controller=RemoteController)
    net.start()
    CLI(net)
    net.stop()
if __name__ == '__main__':
    setLogLevel('info') # output, info, debug
    run()
