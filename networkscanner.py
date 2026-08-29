# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "scapy>=2.7.0",
#     "subnetcalc>=1.0.0",
# ]
# ///
import scapy.all as scapy


def main() -> None:
    test=myscanner("10.15.19.31")
    test.get_target_ip()
    test.scanarp()
class myscanner:
    def __init__(self, ip):
        # Create member variables
        self.ip = ip
        self.lenip = len(ip)

    def get_target_ip(self):
        print(self.ip)
    def scanarp(self):
        pkt=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.ip)
        answered_pkt,unanswered_pkt=scapy.srp(pkt,timeout=2)
        if answered_pkt:
            print("Received answer")
            print(len(answered_pkt))
            queryanswer= (answered_pkt[0][1])
            print(queryanswer)
            #print(queryanswer.show()) detail of answer packet
            print(f"MAC address of {queryanswer.psrc} is {queryanswer.hwsrc}")
        else:
            print("No answer received")


if __name__ == "__main__":
    main()



