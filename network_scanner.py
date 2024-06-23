from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import ARP, Ether, srp, sr1, IP, TCP

class NetworkScanner:
    @staticmethod
    def discover_hosts(ip_range):
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]
        hosts_up = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
        return hosts_up

    @staticmethod
    def scan_ports(ip):
        # Specify the ports to scan
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1723, 3306, 3389, 5900]
        open_ports = []

        for port in ports:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=1, verbose=0)

        return open_ports

class ScanThread(QThread):
    finished = pyqtSignal(list)

    def __init__(self, ip_range):
        super().__init__()
        self.ip_range = ip_range

    def run(self):
        hosts_up = NetworkScanner.discover_hosts(self.ip_range)
        self.finished.emit(hosts_up)

class PortScanThread(QThread):
    finished = pyqtSignal(list, int)  # Emit open_ports and row number

    def __init__(self, ip, row):
        super().__init__()
        self.ip = ip
        self.row = row

    def run(self):
        open_ports = NetworkScanner.scan_ports(self.ip)
        self.finished.emit(open_ports, self.row)
