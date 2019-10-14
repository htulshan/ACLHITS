
import re


class AclHit():
#script to check if a particluar data flow will hit the ACL or not.


    def dict_ace(self, ace):
        #funtion to extract all the components of the ACE, store it in a dictonary.
        aceprotocolreg = '^(?P<seq>\d+) (?P<clause>\w+) (?P<protocol>\w+)'
        match = re.search(aceprotocolreg, ace)

        #to extract sequence numbers permit/deny clause/protocol
        dictace = {
                   "seq": match.group(1),
                   "clause": match.group(2),
                   "protocol": match.group(3)
        }


        dictace["srcip"], dictace["srcmask"] = self.src_ip(ace) #to extract source IP
        dictace["dstip"], dictace["dstmask"] = self.dst_ip(ace) #to extract destination subnet
        dictace["srcportstart"], dictace["srcportend"] = self.source_ports(ace) #to extract source port range
        dictace["dstportstart"], dictace["dstportend"] = self.dst_ports(ace) #to extract destination port range

        return dictace #return dictionary of ace elements

    def source_ports(self, line):

        eqsrcre ='.+eq (\S+).+(?:any|\d+\.\d+\.\d+\.\d+)'
        ltsrcre ='.+lt (\S+).+(?:any|\d+\.\d+\.\d+\.\d+)'
        gtsrcre ='.+gt (\S+).+(?:any|\d+\.\d+\.\d+\.\d+)'
        rangesrcre ='.+range (\S+) (\S+).+(?:any|\d+\.\d+\.\d+\.\d+)'

        eqsrcmatch = re.search(eqsrcre, line)
        if eqsrcmatch:
            return(eqsrcmatch.group(1), eqsrcmatch.group(1))

        else:
            ltsrcmatch = re.search(ltsrcre, line)
            if ltsrcmatch:
                return("1" , str(int(ltsrcmatch.group(1))-1))

            else:
                gtsrcmatch = re.search(gtsrcre, line)
                if gtsrcmatch:
                    return(str(int(gtsrcmatch.group(1))+1), "65535")
                else:
                    rangesrcmatch = re.search(rangesrcre, line)
                    if rangesrcmatch:
                        return(rangesrcmatch.group(1), rangesrcmatch.group(2))
                    else:
                        return('any', 'any') #if no match is found for source port default is any

    def dst_ports(self, line):

        eqdstre ='(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)(?:.+)(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+) eq (\S+)'
        ltdstre ='(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)(?:.+)(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+) lt (\S+)'
        gtdstre ='(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)(?:.+)(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+) gt (\S+)'
        rangedstre ='(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)(?:.+)(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+) range (\S+) (\S+)'

        eqdstmatch = re.search(eqdstre, line)
        if eqdstmatch:
            return(eqdstmatch.group(1), eqdstmatch.group(1))

        else:
            ltdstmatch = re.search(ltdstre, line)
            if ltdstmatch:
                return("1" , str(int(ltdstmatch.group(1))-1))

            else:
                gtdstmatch = re.search(gtdstre, line)
                if gtdstmatch:
                    return(str(int(gtdstmatch.group(1))+1), "65535")
                else:
                    rangedstmatch = re.search(rangedstre, line)
                    if rangedstmatch:
                        return(rangedstmatch.group(1), rangedstmatch.group(2))
                    else:
                        return('any', 'any') #if no match is found for destination ports default is any.

    def src_ip(self, line):

        ipreg = '(host|\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+).*(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)'

        match = re.search(ipreg, line)
        subnet = 'any'
        mask = 'any'
        if match:
            subnet = (match.group(2) if match.group(1) == 'host' else match.group(1))
            mask = ('0.0.0.0' if match.group(1) == "host" else match.group(2))

        return subnet, mask

    def dst_ip(self, line):

        ipreg = '(?:host \d+\.\d+\.\d+\.\d+|any|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+).*(host|\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)'

        match = re.search(ipreg, line)
        subnet = 'any'
        mask = 'any'
        if match:
            subnet = (match.group(2) if match.group(1) == 'host' else match.group(1))
            mask = ('0.0.0.0' if match.group(1) == "host" else match.group(2))

        return subnet, mask


    def protocol_to_port(self, acelist):
    #for converting well known protocols to there respetive port numbers


        map = {
            'biff':'512',
            'bootpc':'68',
            'bootps':'67',
            'discard':'9',
            'dnsix':'195',
            'domain':'53',
            'echo':'7',
            'isakmp':'500',
            'mobile-ip':'434',
            'nameserver':'42',
            'netbios-dgm':'138',
            'netbios-ns':'137',
            'netbios-ss':'139',
            'non500-isakmp':'4500',
            'ntp':'123',
            'pim-auto-rp':'496',
            'rip':'520',
            'ripv6':'521',
            'snmp':'161',
            'snmptrap':'162',
            'sunrpc':'111',
            'syslog':'514',
            'tacacs':'49',
            'talk':'517',
            't':'69',
            'time':'37',
            'who':'513',
            'xdmcp':'177',
            'bgp':'179',
            'chargen':'19',
            'cmd':'514',
            'daytime':'13',
            'discard':'9',
            'domain':'53',
            'echo':'7',
            'exec':'512',
            'finger':'79',
            'ftp':'21',
            'ftp-data':'20',
            'gopher':'70',
            'hostname':'101',
            'ident':'113',
            'irc':'194',
            'klogin':'543',
            'kshell':'544',
            'login':'513',
            'lpd':'515',
            'msrpc':'135',
            'nntp':'119',
            'onep-plain':'15001',
            'onep-tls':'15002',
            'pim-auto-rp':'496',
            'pop2':'109',
            'pop3':'110',
            'smtp':'25',
            'sunrpc':'111',
            'syslog':'514',
            'tacacs':'49',
            'talk':'517',
            'telnet':'23',
            'time':'37',
            'uucp':'540',
            'whois':'43',
            'www':'80'
            }


        for i in range(len(acelist)):
            if acelist[i] in list(map.keys()):
                acelist[i] = map[acelist[i]]

        return " ".join(acelist)


    def check_for_hit(self, srcip, dstip, L4protocol, srcport, dstport, acelist, aceraw):
            #check if the input packets hits a particular ACE or not.

            hits = []
            for line in acelist:

                #if the ACE protocol is IP
                if line["protocol"] == "ip":
                    if line["srcip"] == "any" or self.subnet_hit(srcip, line["srcip"], line["srcmask"]):
                        if line["dstip"] == "any" or self.subnet_hit(dstip, line["dstip"], line["dstmask"]):
                            for line1 in aceraw:
                                if line1[0] == line["seq"]:
                                    hits.append(" ".join(line1))

                #if ACE protocol is TCP or UDP
                if line["protocol"] == L4protocol and line["protocol"] != "ip":
                    if line["srcip"] == "any" or self.subnet_hit(srcip, line["srcip"], line["srcmask"]):
                        if line["dstip"] == "any" or self.subnet_hit(dstip, line["dstip"], line["dstmask"]):
                            if line["srcportstart"] == "any" or (srcport != "any" and int(srcport) >= int(line['srcportstart']) and int(srcport) <= int(line['srcportend'])):
                                if line["dstportstart"] == "any" or (dstport != "any" and int(dstport) >= int(line['dstportstart']) and int(dstport) <= int(line['dstportend'])):
                                    for line1 in aceraw:
                                        if line1[0] == line["seq"]:
                                            hits.append(" ".join(line1))


            return hits #return a list of matched ACEs

    def subnet_hit(self, ip, subnet, mask):
        #to check if the ip is part of the subnet given

        binaryformat = "{:08b}"*4

        iplist = ip.split(".")
        ipbinary = binaryformat.format(int(iplist[0]), int(iplist[1]), int(iplist[2]), int(iplist[3]))

        subnetlist = subnet.split(".")
        subnetbinary = binaryformat.format(int(subnetlist[0]), int(subnetlist[1]), int(subnetlist[2]), int(subnetlist[3]))

        masklist = mask.split(".")
        maskbinary = binaryformat.format(int(masklist[0]), int(masklist[1]), int(masklist[2]), int(masklist[3]))

        i = maskbinary.count("0") #counting the number of relevant bits

        iprelevant = ipbinary[:i]
        subnetrelevant = subnetbinary[:i]

        if iprelevant == subnetrelevant: #to check if relevant subnet port in found in ip or not
            return True

        else:
            return False


    def main(self):
        #these are exception KWs, if these KWs are found in any ACE the ACE will not be processed and it will be printed seprately
        exception = ['remark', 'dscp', 'neq', 'ttl', 'ack', 'icmp', 'gre', 'rst', 'psh', 'pim', 'igmp', 'syn', 'established', 'pcp', 'eigrp', 'nos', 'option',
            'tos', 'fragments', 'urg', 'time-range', 'object-group', 'fin', 'ahp', 'precedence', 'ospf', 'esp'] #all the exception KW

        print("="*120)
        print(f"This script can be used to check if a particluar packet of type (source IP, destination IP, protocol [TCP, UDP, IP]source port, destination port) \nwill hit a particular entry in the given access list or not. The script can process only certain types of ACEs and will\nnot be to process ACEs containing the following KW:\n {exception}\nThe script however will print ACE containing the exception KWs seprately and will process the non-exception ACEs")
        print("="*120)

        srcport = "any" #saves the source port of the packet
        dstport = "any" #saves the destinatin port of the packet
        srcip = "" #saves the sources ip of the packet
        dstip = "" #saves the destination IP of the packet
        L4protocol = "" #saves the L4 portocol type
        acelist = [] #save the list dictionaries of all the ACEs
        aceraw = [] #saves the ACEs in a list
        aceport = ""

        #taking input from user

        srcip = input("Enter the source IP: ")
        dstip = input("Enter the desctination IP: ")
        L4protocol = input("Enter the L4 protocol [ip]: ")
        if L4protocol == "" or L4protocol == "ip":
            L4protocol = "ip"
        else:
            srcport = input("Enter the source port [any]: ")
            if srcport == "":
                srcport = "any"

            dstport = input("Enter the dest port [any]: ")
            if dstport == "":
                dstport = "any"

        aclfile = input("Enter the name of the ACL file: ")

        with open(aclfile, "r") as f:
            exceptions = [] #to save all the exception ACE which the script will not be able to process



            for line in f:
                #checking if this is a exception ACE entry
                exceptioncase = False
                ace = line.rstrip()

                #to check if any of the exection KWs is present in the ACE or not
                for e in exception:
                    if e in ace.split():
                        exceptioncase = True
                        exceptions.append(ace)
                        break
                if exceptioncase:
                    continue

                #to check if the protocol is not a number
                if ace.split()[2].isdigit():
                    exceptions.append(ace)
                    continue

                aceport = self.protocol_to_port(ace.split()) #takes a list retrun a string

                #to check if we have multiple source ports or multiple destination port in the ACEs
                mutipleportreg = '.*eq \d+ \d+(?:\s|$)'
                match = re.search(mutipleportreg, aceport)
                if match:
                    exceptions.append(ace)
                    continue

                aceraw.append(ace.split())
                acelist.append(self.dict_ace(aceport))#extracting all the components of the ACE in dictionary


            #printing all the expception ACEs
            if exceptions:
                print("="*60)
                print("Script could not process the following lines in ACL:")
                for line in exceptions:
                    print(line)
                print("="*60)


        #checking if there is a hit between the ACL and the input packet.
        hits = self.check_for_hit(srcip, dstip, L4protocol, srcport, dstport, acelist, aceraw)

        #prints the result
        if hits:
            print("="*60)
            print("The following lines are found as hits in the ACL")
            for line in hits:
                print(line)
            print("="*60)

        else:
            print("="*60)
            print("There were no hits in the ACL, packet will hit the default deny statement.")
            print("="*60)



if __name__ == "__main__":

    test = AclHit()
    test.main()
    input("Press Return to Exit")
