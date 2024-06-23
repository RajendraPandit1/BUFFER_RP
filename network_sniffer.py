from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, TCP, UDP, ICMP, Raw
import base64
from datetime import datetime

class NetworkSniffer(QThread):
    packet_received = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.stop_sniffing = False

    def run(self):
        while not self.stop_sniffing:
            sniff(prn=self.process_packet, count=1)

    def process_packet(self, packet):
        packet_info = {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": None,
            "Destination IP": None,
            "Protocol": None,
            "Source Port": None,
            "Destination Port": None,
            "Type": None,
            "Code": None,
            "Payload": None
        }

        if "IP" in packet:
            packet_info["Source IP"] = packet["IP"].src
            packet_info["Destination IP"] = packet["IP"].dst

        if TCP in packet:
            packet_info["Protocol"] = "TCP"
            packet_info["Source Port"] = packet[TCP].sport
            packet_info["Destination Port"] = packet[TCP].dport
            if Raw in packet:
                packet_info["Payload"] = self.decode_payload(packet[Raw].load)

        elif UDP in packet:
            packet_info["Protocol"] = "UDP"
            packet_info["Source Port"] = packet[UDP].sport
            packet_info["Destination Port"] = packet[UDP].dport
            if Raw in packet:
                packet_info["Payload"] = self.decode_payload(packet[Raw].load)

        elif ICMP in packet:
            packet_info["Protocol"] = "ICMP"
            packet_info["Type"] = packet[ICMP].type
            packet_info["Code"] = packet[ICMP].code
            if Raw in packet:
                packet_info["Payload"] = self.decode_payload(packet[Raw].load)

        # Check if any information is present in the packet
        if any(value is not None for value in packet_info.values()):
            self.packet_received.emit(packet_info)

    def decode_payload(self, payload):
        try:
            decoded_payload = payload.decode('utf-8')
            return decoded_payload
        except UnicodeDecodeError:
            return base64.b64encode(payload).decode('utf-8')
