# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "scapy>=2.7.0",
#     "subnetcalc>=1.0.0",
# ]
# ///
import scapy.all as scapy
from subnetcalc import Ip   


def main() -> None:
    test=myscanner("10.15.19.35/28")
    test.ipinformation()
    test.ip_range()
    #test.scanarp()
class myscanner:
    def __init__(self, ip):
        # Create member variables
        self.ip = ip
        self.ip_range_list=[]
        self.instanceip= Ip (self.ip)
     
    def ipinformation(self):
        print(self.instanceip)

    def ip_range(self):
        ip_ranges= self.instanceip.available_ips
        for a in ip_ranges:
            self.ip_range_list.append(a)
            #print(a)
    
    def scanarp(self):
        for x in self.ip_range_list:
            pkt=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=x)
            answered_pkt,unanswered_pkt=scapy.srp(pkt,timeout=1,verbose=0)
            if answered_pkt:
                #print("Received answer")
                #print(len(answered_pkt))
                queryanswer= (answered_pkt[0][1])
                #print(queryanswer)
                #print(queryanswer.show()) #detail of answer packet
                print(f"MAC address of {queryanswer.psrc} is {queryanswer.hwsrc}")
            else:
                #print("No answer received")
                pass


if __name__ == "__main__":
    main()
