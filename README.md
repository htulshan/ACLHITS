Motivation:
ACLs which contain thousands of ACEs are diffeicult to parse and check if a particular packet flow will match a certain ACE or not.

Objective:
To find if a particluar packet flow will hit any ACE in the ACL.

Script logic to achieve the objective:
1) The script will take input from user in the format :

Enter the source IP: 2.2.2.2
Enter the desctination IP: 1.1.1.1
Enter the L4 protocol [ip]: tcp
Enter the source port [any]: 21
Enter the dest port [any]: 9
Enter the name of the ACL file: acl3


2) The access list should be saved in a file and is given as an input to the script (acl3 in the above case)
3) The script will scan the entire access list looking for a hit and will print all the possible hits in the access iplist
4) The script can process only basic (mostly used ) ACE formats.
5) If there is a particular ACE which the cannot process the script will not crash rather it will print the ACE seperatly to the manually check for hits.

Assumptions:

The script is to be run on an end device.
The access list format usedd is that of Cisco Routers/switches running IOS XE/IOS

Test Output :
htulshan@htulshan-Lenovo-Z51-70:~/Documents/python test scripts$ python3 aclhits.py
========================================================================================================================
This script can be used to check if a particluar packet of type (source IP, destination IP, protocol [TCP, UDP, IP]source port, destination port)
will hit a particular entry in the given access list or not. The script can process only certain types of ACEs and will
not be to process ACEs containing the following KW:
 ['remark', 'dscp', 'neq', 'ttl', 'ack', 'icmp', 'gre', 'rst', 'psh', 'pim', 'igmp', 'syn', 'established', 'pcp', 'eigrp', 'nos', 'option', 'tos', 'fragments', 'urg', 'time-range', 'object-group', 'fin', 'ahp', 'precedence', 'ospf', 'esp']
The script however will print ACE containing the exception KWs seprately and will process the non-exception ACEs
========================================================================================================================
Enter the source IP: 2.2.2.2
Enter the desctination IP: 1.1.1.1
Enter the L4 protocol [ip]: tcp
Enter the source port [any]: 21
Enter the dest port [any]: 9
Enter the name of the ACL file: acl3
============================================================
Script could not process the following lines in ACL:
    1630 permit tcp host 2.2.2.2 eq 10 15 host 1.1.1.1
    1640 permit tcp host 2.2.2.2 host 1.1.1.1 eq 10 15
    1650 permit tcp host 2.2.2.2 eq ftp-data 500 host 1.1.1.1
    1660 permit tcp host 2.2.2.2 host 1.1.1.1 eq ftp-data 500
============================================================
============================================================
The following lines are found as hits in the ACL
10 permit ip any any
20 permit ip any host 1.1.1.1
40 permit ip host 2.2.2.2 any
50 permit ip host 2.2.2.2 host 1.1.1.1
80 permit ip 2.2.0.0 0.0.255.255 any
90 permit ip 2.2.0.0 0.0.255.255 host 1.1.1.1
100 permit tcp any any
140 permit tcp any host 1.1.1.1
220 permit tcp host 2.2.2.2 any
260 permit tcp host 2.2.2.2 host 1.1.1.1
380 permit tcp 2.2.0.0 0.0.255.255 any
420 permit tcp 2.2.0.0 0.0.255.255 host 1.1.1.1
460 permit tcp any any
480 permit tcp any any lt 10
500 permit tcp any host 1.1.1.1
520 permit tcp any host 1.1.1.1 lt 10
580 permit tcp host 2.2.2.2 any
600 permit tcp host 2.2.2.2 any lt 10
620 permit tcp host 2.2.2.2 host 1.1.1.1
640 permit tcp host 2.2.2.2 host 1.1.1.1 lt 10
740 permit tcp 2.2.0.0 0.0.255.255 any
750 permit tcp 2.2.0.0 0.0.255.255 any lt 10
780 permit tcp 2.2.0.0 0.0.255.255 host 1.1.1.1
790 permit tcp 2.2.0.0 0.0.255.255 host 1.1.1.1 lt 10
820 permit tcp any any
830 permit tcp any gt ftp-data any
860 permit tcp any host 1.1.1.1
870 permit tcp any gt ftp-data host 1.1.1.1
940 permit tcp host 2.2.2.2 any
950 permit tcp host 2.2.2.2 gt ftp-data any
980 permit tcp host 2.2.2.2 host 1.1.1.1
1010 permit tcp host 2.2.2.2 gt ftp-data host 1.1.1.1
1100 permit tcp 2.2.0.0 0.0.255.255 any
1130 permit tcp 2.2.0.0 0.0.255.255 gt ftp-data any
1140 permit tcp 2.2.0.0 0.0.255.255 host 1.1.1.1
1170 permit tcp 2.2.0.0 0.0.255.255 gt ftp-data host 1.1.1.1
1180 permit ip any any
1190 permit ip any host 1.1.1.1
1210 permit ip host 2.2.2.2 any
1220 permit ip host 2.2.2.2 host 1.1.1.1
1250 permit ip 2.2.0.0 0.0.255.255 any
1260 permit ip 2.2.0.0 0.0.255.255 host 1.1.1.1
1270 permit tcp any any
1280 permit tcp any range ftp-data 500 any
1310 permit tcp any host 1.1.1.1
1320 permit tcp any range ftp-data 500 host 1.1.1.1
1390 permit tcp host 2.2.2.2 any
1400 permit tcp host 2.2.2.2 range ftp-data 500 any
1430 permit tcp host 2.2.2.2 host 1.1.1.1
1460 permit tcp host 2.2.2.2 range ftp-data 500 host 1.1.1.1
1550 permit tcp 2.2.0.0 0.0.255.255 any
1580 permit tcp 2.2.0.0 0.0.255.255 range ftp-data 500 any
1590 permit tcp 2.2.0.0 0.0.255.255 host 1.1.1.1
1620 permit tcp 2.2.0.0 0.0.255.255 range ftp-data 500 host 1.1.1.1
============================================================
Press Return to Exit
htulshan@htulshan-Lenovo-Z51-70:~/Documents/python test scripts$
