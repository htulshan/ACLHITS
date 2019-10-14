Motivation:
ACLs which contain thousands of ACEs are difficult to parse and check if a particular packet flow will match a certain ACE or not.

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

Test Outputs in output file.
