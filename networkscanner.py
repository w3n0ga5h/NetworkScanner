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
    test=myscanner("45.33.32.140/29")
    #test.ipinformation()
    test.ip_range()
    #test.scanarp()
    test.stealth_port_scan()

class myscanner:
    def __init__(self, ip):
        # Create member variables
        self.ip = ip
        self.ip_range_list=[]
        self.instanceip= Ip (self.ip)
        self.basic_tcp_port_list=[21,22,80,443,445]    
    def ipinformation(self):
        print(self.instanceip)

    def ip_range(self):
        if self.instanceip.cidr == '32':
            pass
        else:
            ip_ranges= self.instanceip.available_ips
            for a in ip_ranges:
                self.ip_range_list.append(a)

    def scanarp(self):
        print("Starting ARP Scan :")
        if self.instanceip.cidr == '32':
            pkt=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.instanceip.ip)
            answered_pkt,unanswered_pkt=scapy.srp(pkt,timeout=1,verbose=0)
            if answered_pkt:
                #print("Received answer")
                #print(len(answered_pkt))
                queryanswer= (answered_pkt[0][1])
                #print(queryanswer)
                #print(queryanswer.show()) #detail of answer packet
                print(f"IP :{queryanswer.psrc} answered and the MAC address is {queryanswer.hwsrc}")
            else:
                #print("No answer received")
                pass            
        else:
            for x in self.ip_range_list:
                pkt=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=x)
                answered_pkt,unanswered_pkt=scapy.srp(pkt,timeout=1,verbose=0)
                if answered_pkt:
                    #print("Received answer")
                    #print(len(answered_pkt))
                    queryanswer= (answered_pkt[0][1])
                    #print(queryanswer)
                    #print(queryanswer.show()) #detail of answer packet
                    print(f"IP :{queryanswer.psrc} answered and the MAC address is {queryanswer.hwsrc}")
                else:
                    #print("No answer received")
                    pass
                
    def stealth_port_scan(self):      
        if self.instanceip.cidr == '32':
            print(f"Starting stealth port scan of {self.instanceip.ip}")
            for each_port in self.basic_tcp_port_list:
                pkt=scapy.IP(dst=self.instanceip.ip,proto=6)/scapy.TCP(dport=each_port,flags="S")
                #print(pkt.show())   
                answer_pkt=scapy.sr1(pkt,timeout=1,verbose=0)
                if answer_pkt:
                #print("Received answer")
                #print(len(answer_pkt))
                #print(answer_pkt)
                    scan_answer= (answer_pkt[0][1])
                #print(scan_answer)
                #print(scan_answer.flags) #detail of answer packet
                    if scan_answer.flags =="SA":
                        print(f"SynAck answer received from port {pkt.dport}")
                        close_pkt=scapy.IP(dst=self.instanceip.ip,proto=6)/scapy.TCP(dport=each_port,flags="A")
                        scapy.sr1(close_pkt,timeout=1,verbose=0)
                #print(f"IP :{queryanswer.psrc} answered and the MAC address is {queryanswer.hwsrc}")
                else:
                    print("No received answer")
        else:
            print(self.ip_range_list)
            for x in self.ip_range_list:
                print("test")
                print(f"Starting stealth port scan of {x}")
                for each_port in self.basic_tcp_port_list:
                    pkt=scapy.IP(dst=self.instanceip.ip,proto=6)/scapy.TCP(dport=each_port,flags="S")
                    #print(pkt.show())   
                    answer_pkt=scapy.sr1(pkt,timeout=1,verbose=0)
                    if answer_pkt:
                    #print("Received answer")
                    #print(len(answer_pkt))
                    #print(answer_pkt)
                        scan_answer= (answer_pkt[0][1])
                    #print(scan_answer)
                    #print(scan_answer.flags) #detail of answer packet
                        if scan_answer.flags =="SA":
                            print(f"SynAck answer received from port {pkt.dport}")
                            close_pkt=scapy.IP(dst=self.instanceip.ip,proto=6)/scapy.TCP(dport=each_port,flags="A")
                            scapy.sr1(close_pkt,timeout=1,verbose=0)
                    #print(f"IP :{queryanswer.psrc} answered and the MAC address is {queryanswer.hwsrc}")
                    else:
                        print("No received answer")
    def port_scan(self):
        pass
if __name__ == "__main__":
    main()
