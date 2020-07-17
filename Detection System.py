from scapy.all import sniff, TCP, UDP


class DetectionSystem(object):
    def __init__(self):
        self.sniffed_packets = {}
        self.previous_packet = None
        self.packets_file_name = "CAPTURED_PACKETS.txt"
        self.THRESHOLD_LIMIT = 200      # This is the amount of continous packets it needs to match to report it as malicious activity
        # Using a dictionary here to store some data
        self.data = {
            "IP_PACKETS" : 0,
            "TCP_PACKETS" : 0,
            "UDP_PACKETS" : 0,
            "ALERT_COUNTER" : 0,
        }
        return None
    def start_sniffing(self, timeout=15):
        #This function starts sniffing on all interfaces and stops after the timeout
        # Default timeout is None, which means it will run forever. So, for that I have set timeout as 15, if no value is passed.
        print("Sniffing for {} seconds".format(timeout))
        self.sniffed_packets = sniff(timeout=timeout)  #Saves all the captured packets in this variable
        return None
    #
    def parse_packets(self):
        # Simple for loop which checks if the current packet is TCP, then uses built-in function sum() to add these truthy values.
        self.data["TCP_PACKETS"] = sum(TCP in each_packet for each_packet in self.sniffed_packets)
        self.data["UDP_PACKETS"] = sum(UDP in each_packet for each_packet in self.sniffed_packets)
        self.data["IP_PACKETS"] = self.data["TCP_PACKETS"] + self.data["UDP_PACKETS"]
        print ("Total number of ip packets: ", self.data["IP_PACKETS"])
        print ("Total number of tcp packets: ", self.data["TCP_PACKETS"])
        print ("Total number of udp packets: ", self.data["UDP_PACKETS"])
        for each_packet in self.sniffed_packets:
            packets_match = False  # This variable is set to False at the beginning of each loop
            if self.data["ALERT_COUNTER"] > self.THRESHOLD_LIMIT:  # If the alert_counter is more than the threshold_limit[200] it prints the alert
                print("Malicious activity found, please check the network, alert rating:{}".format(self.data["ALERT_COUNTER"]))
                break # break the loop if alert is raised, so the user can see

            #Checks if self.previous_packet and each_packet is defined because on the first iteration self.previous_packet is None
            if self.previous_packet and each_packet:
                if (TCP in each_packet) or (UDP in each_packet): #Checks for packet protocol which should either be TCP or UDP
                    #Previous Packet
                    # pp_src_port = self.previous_packet.sport     #The values for port, src_ip, etc can be got using this method also,
                    # pp_src_ip = self.previous_packet.src         #but if a value is not available it returns None. Then the whole program stops midway.
                    # pp_dst_ip = self.previous_packet.dst         #So, I have used the sprintf method, you can delete this stuff.
                    # pp_dst_port = self.previous_packet.dport
                    # PP = Previous Packet
                    pp_src_ip = self.previous_packet.sprintf("{IP:%IP.src%}")
                    pp_src_port = self.previous_packet.sprintf("{IP:%IP.sport%}")
                    pp_dst_ip = self.previous_packet.sprintf("{IP:%IP.dst%}")
                    pp_dst_port = self.previous_packet.sprintf("{IP:%IP.dport%}")
                    pp_len = self.previous_packet.sprintf("{IP:%IP.len%}")
                    #
                    #CP = Current Packet
                    # cp_src_ip = each_packet.src
                    # cp_src_port = each_packet.sport
                    # cp_dst_ip = each_packet.dst
                    # cp_dst_port = each_packet.dport
                    #Current Packet
                    cp_src_ip = each_packet.sprintf("{IP:%IP.src%}")
                    cp_src_port = each_packet.sprintf("{IP:%IP.sport%}")
                    cp_dst_ip = each_packet.sprintf("{IP:%IP.dst%}")
                    cp_dst_port = each_packet.sprintf("{IP:%IP.dport%}")
                    cp_len = self.previous_packet.sprintf("{IP:%IP.len%}")
                    if cp_src_ip == cp_dst_ip:
                        #If source and destination Ip are same 0.0.0.0 , skip it
                        continue
                    print("---------------------------------------------------\n")
                    if pp_src_ip == cp_src_ip: # Checks if previous src ip and the current src ip are same
                        print("PP SRC Ip : ", pp_src_ip)
                        print("CP SRC Ip : ", cp_src_ip)
                        print("SRC Ips are same for previous and current packet")
                        print("\n")
                        if pp_dst_ip == cp_dst_ip: # Checks if previous dst ip and the current dst ip are same
                            print("PP DEST IP : ", pp_dst_ip)
                            print("CP DEST IP : ", cp_dst_ip)
                            print("DEST Ips are same for previous and current packet")
                            print("\n")
                            if pp_src_port == cp_src_port: # Checks if previous src port and the current src port are same
                                print("PP SRC Port : ", pp_src_port)
                                print("CP SRC Port : ", cp_src_port)
                                print("SRC Ports are same for previous and current packet")
                                print("\n")
                                if pp_dst_port == cp_dst_port: # Checks if previous dest port and the current dest port are same
                                    print("PP DEST Port : ", pp_dst_port)
                                    print("CP DEST Port : ", cp_dst_port)
                                    print("DEST Ports are same for previous and current packet")
                                    print("\n")
                                    if pp_len == cp_len: # Checks if previous request length and the current request length are same
                                        print("PP len : ", pp_len)
                                        print("CP len : ", cp_len)
                                        print("len are same for previous and current packet")
                                        print("\n")
                                    #If all the above if's are True then the ALERT_COUNTER will be appended
                                    # This below block should be indented if you want to match request lengths also
                                    # ################  start block ############
                                    self.data["ALERT_COUNTER"] += 1
                                    print("Alert Counter : ", self.data["ALERT_COUNTER"])
                                    packets_match = True # The variable defined at the beginning of loop is set to True, if it is an alert.
                                    #################### end block #############
                #This is where the current packet will be set as previous packet as the loop is over
                self.previous_packet = each_packet
                if not packets_match: # If this is False, the counter resets
                    self.data["ALERT_COUNTER"] = 0
                    print("Resetting Alert Counter")
            else:
                # This is for the first_iteration when self.previous_packet will be none
                self.previous_packet = each_packet
            print("---------------------------------------------------\n")
        return None
    #
    def main(self):
        # Start Sniffing
        self.start_sniffing(timeout=10)
        #Parse Packets
        self.parse_packets()
        return None



detector = DetectionSystem()
detector.main()
