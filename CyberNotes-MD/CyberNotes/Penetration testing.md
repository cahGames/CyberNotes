**COMMON TOOLS:**

<ins>Nmap</ins>: port scanning utility

- typical command you want to run: `sudo nmap -vv -sC -sV 127.0.0.1`
- `-p` option (by default Nmap scans the most common 1000 ports for each protocol):
    - `-p 80` scans only port 80
    - `-p 1000-1500` scans only from port 1000 to 1500
    - `-p-` scans all the 65535 ports.
- scan types:
    - `-sT (TCP Connect scan)`: nmap tries to perform the TCP three-way handshake (SYN, SYN/ACK, ACK) to each port:
        - if after the initial SYN packet, the server returns a packet with the RST flag set, then nmap can establish the port is closed
        - if the server does not respond, the port is considered **filtered**, because there's probably a firewall that is configured to just drop certain incoming packets.
            However that's not always the case, because a firewall can also be configured to respond with a RST TCP packet (this makes it difficult to get an accurate reading of a target).
    - `-sS (SYN scans)`: similar to tcp scans, but nmap sends a RST packet after receiving a SYN/ACK from the server. These are the default scans of nmap if run with sudo permissions.
        - *Advantages*:
            - it can be used to bypass older Intrusion Detection systems, as they are looking for a full three way handshake (for this reason they are also referred as "stealth" scans)
            - these types of scans are often not logged by applications, as standard practice is to log a connection once it's been fully established
            - they are faster than TCP Connect scans, as nmap doesn't have to bother about disconnecting after the handshake
        - *Disadvantages:*
            - they require sudo permissions
            - unstables services are sometimes brought down by SYN scans
    - `-sU (UDP scans)`: nmap send UDP packets to the server and hopes to receive a response. These scans are MUCH slower than TCP scans.
        - if the server responds with a UDP packet (very unusual) then the server marked the port as open.
        - if the server doesn't respond, it marks the port as open|filtered
        - if the server responds with a IMCP packet with a message saying the port is unreachable, then nmap mark the port as closed
    - `-sN (NULL scans)`: nmap send a TCP request with no flags set at all. This is a stealth scan, used to bypass firewalls that drop incoming TCP packets which have the SYN flag set.
        - the server should respond with a RST packet if the port is closed
        - if the port is open, or if there's a firewall, there SHOULD (according to RFC 793) be no response to the malformed packet, and the port is marked as open|filtered.
        - if the target responds with an ICMP unreachable packet, the port is marked as filtered
    - `-sF (FIN scans)`: nmap send a TCP request with the FIN flag set. Same considerations as -sN
    - `-sX (Xmas scans)`: sends a malformed TCP packet. Same considerations as -sN
    - **ICMP Network Scanning**: if we want to perform a 'ping sweep', we use the -sn switch (don't scan any ports) specifying the IP range with either a hyphen:
        `nmap -sn 192.168.0.1-254`
        or CIDR notation:
        `nmap -sn 192.168.0.0/24`
        - if ran on a local network as sudo, it relies on ARP requests, otherwise on ICMP echo packets
        - some firewalls (like the Windows one) block all ICMP packets. We can force nmap to scan every IP without trying to ping it first by using the option `-Pn`. The downside of course is that this type of scan requires a LOT of time.
- other common firewalls evasion techniques:
    - `--badsum`: used to generate invalid checksum for packets. Can be used to determine the **presence** of a firewall/IDS, since these may potentially respond without checking the checksum. If there's not a firewall, the packet instead reaches the host and is immediately dropped as soon as the checksum is checked.
    - `-f` or `--mtu <number>` to fragment the packets (automatically in the first case, manually in the second)
    - `--scan-delay  <time>ms` to add a delay between packets sent. Useful to evade any time-based triggers of firewalls/IDS
- NSE (Nmap scripting engine): executes scripts written in Lua language, that can scan for vulnerabilities or even automate exploits
    - every script is of a category that identify how much impactful on the target the script is (safe, intrusive, etc.)
    - to execute scripts there's the switch --script, that can be used in multiple ways: `--script=<category>` or `--script=<name_of_script> --script-args scriptname.arg1=value,scriptname.arg2=value2,(...)`
- useful links:
    - https://nmap.org/nsedoc/   for a complete list of nse scripts (also present in `/usr/share/nmap/scripts`, with the complete list in scripts.db)
    - https://nmap.org/book/man-bypass-firewalls-ids.html  for more ways of bypassing firewalls

<ins>Hydra</ins>: password cracking tool that can perform dictionary attacks against more than 50 protocols

- basic syntax: `hydra -t 4 -l user -P /usr/share/wordlists/rockyou.txt -vV 10.10.10.6 ftp`
    - -t : number of parallel connections per target
    - -l : the name of the user
    - -P : the path of the wordlist
    - -vV : verbose mode
    - ftp: the type of protocol

**OTHER:**

<ins>Network services (with exploitation)</ins>:

- *Useful links*:
    - https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-exploits.html
- **SMB**: (default ports: 139 for NetBIOS, 445 for TCP/IP)
    - *Description*:
        - response-request protocol used to share various resources on a network
        - client first establishes a connection with the server, then it can sends commands to share, open, read and write files.
        - runs on windows, and also linux through an open source server called Samba
        - SMB share: a sort of filesystem that can be private or anonymous (a.k.a. public)
    - *Enumeration*:
        - `enum4linux`is a good tool to do that (already installed in Kali). The usual command you want to run is: `enum4linux -a 10.10.10.10`
    - *Exploitation*:
        - (*pretty rare*) CVE-2017-7494: allows RCE without even having any authorization
        - most likely due to misconfigurations in the system, like an anonymous share that contains sensitive information.
        - to connect to a share we use `SMBClient` like this: `smbclient //IP/SHARE -U user -p port`
            - if we want to access to an anonymous share, instead of `-U` we use the option `-N`
- **Telnet**: (default ports: 23)
    - *Description*:
        - telnet is an application protocol (client-server) that let you connect and execute commands on a remote machine that is hosting a telnet server
        - WAY more unsafe than ssh, all messages are sent in clear text and there are no specific security mechanisms
    - *Enumeration*:
        - there are no specific tools, nmap is sufficient to do that
    - *Exploitation*:
        - to connect to a telnet server we use the command `telnet ip port`
        - again, misconfiguration mistakes create vulnerabilities
- **FTP**: (default ports: 21)
    - *Description*:
        - client-server protocol used to allow remote transfer of files over a network
        - command channel, used for transmitting commands, and data channel, used for transmitting data
        - FTP server may support wither active or passive connections, or both
            - Passive FTP connection, the server opens a port and the client connects to it
            - Active FTP connection, the client opens a port and listen. The server is required to actively connect to it
        - FTP share: sort of filesystem that can be protected or anonymous (you don't need login credentials to access it)
    - *Enumeration*:
        - there are no specific tools to do that, nmap is sufficient to reveal any anonymous shares
        - with some FTP servers it's possible to enumerate all the users without being authenticated by using the command cwd (https://www.exploit-db.com/exploits/20745)
    - *Exploitation*:
        - to connect to a ftp server use the command `ftp ip port`. The server will then ask for a username and a password.
            If you want to login anonymously, type `anonymous` in the username prompt, and just hit return when it asks for a password.
        - use `ls` to list files and directories in the remote directory, `get` to download a file from the remote machine, `put` to upload a local file to the remote machine
        - FTP traffic is unencrypted, leaving it vulnerable to a man-in-the-middle attack
- **NFS**: (default ports: 111, 2049 for daemon)
    - *Description*:
        - used for file sharing between computers
        - the client first requests the server to mount a remote directory on a local directory (the same way it can mount a physical device).
        - the mount service checks if the user has the permission to access those files, and returns a file handle which identifies every file and directory on the server.
        - when a user wants to access a file, an RCP call to NSFD (NSF daemon) is made with the appropriate parameters
    - *Enumeration*:
        - use the command `showmount -e ip` to list all the visible NFS shares
    - *Exploitation*:
        - to access a NFS share, we have to use this command: `sudo mount -t nfs IP:share /tmp/mount/ -nolock`
        - privilege escalation with NFS server active: if we have a low privilege shell, and we have access to the NFS share, we can upload an executable file with the SUID bit set to get a shell with root privileges.
            **NOTE**: this works ONLY if "**root squashing**"is disabled! If it's enabled, this prevents anyone connecting to the NFS share from having root access.
- **SMTP**: (default ports: 25)
    - *Description*:
        - it's one of two protocols necessary for email transfer. SMTP is used to handle the sending (and part of the reception) of messages:
            - first the mail user agent (email client or external program) connects to its SMTP server (example: smtp.gmail.com) with a **SMTP handshake** (won't be shown in detail here)
            - if the recipient's domain is the same of the SMTP server (example: john@gmail.com), the SMTP just sends the email to the respective POP/IMAP server. Otherwise, if it's different (example: john@yahoo.com), it makes a request to a DNS server to get the ip of the right SMTP server.
            - once the ip is found, the SMTP server makes a connection to the recipient's SMTP server. If it fails to do that, the email gets put into an SMTP queue
            - the recipient's SMTP server receives the email and checks if the domain and the user name of the incoming email have been recognised. And then it forwads the email to the right POP/IMAP server.
        - The POP/IMAP server handles part of the reception of the emails and uses two protocols: POP and IMAP
            - POP downloads all the messages from the inbox to the client, IMAP just downloads the new messages.
    - *Enumeration*:
        - vulnerable mail servers can provide an inital foothold into a network
        - to find out the version of an SMTP server we can use the "smtp_version" module of MetaSploit
        - to enumerate users, we can use the "smtp_enum" module of MetaSploit, which uses two internal commands of SMTP: VRFY to verify the name of valid users, and EXPN which reveals the actual address of user's aliases and lists of e-mail
        - an alternative to that is the command `smtp-user-enum`
- **MySQL:** (default ports: 3306)
    - NOTE: here I do **NOT** explain SQL injections (check the web security module for that). Here I explain what to do in case a server has a MySQL port open!
    - *Description*:
        - RDBMS, Relational Database Management System
        - commonly used as backend database for webservers
        - In MySQL the keyword "SCHEMA" is the same as "DATABASE"
        - MySQL hashes are used to index data into a hash table, so that searching and accessing data is more efficient
    - *Enumeration*:
        - usually not the first point of call when getting inital information on a server.
        - we can connect to a MySQL server using the command `mysql -h IP -P port -u username -p`
        - in alternative we can use the "mysql_sql" module of metasploit
        - we can also use the "mysql\_schemadump" module to dump all the structure of databases (this returns a LOT of data) or the "mysql\_hashdump" module to dump all the MySQL hashes (included eventual hashed passwords!)

endpoint discovery (also called forced browsing) with gobuster:

`gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt -x php, html`

- -x is optional and it tells gobuster to search also for file with .php and .html extensions

<ins>How to follow redirects to unknown hosts</ins>:

Problem: you scan all the ports of a machine, you find a webserver, you try to connect to the webserver, but it automatically redirects you to some weird host like `weirdwebsite.htb`. Since the classic DNS server can't resolve the host, you can't access to the webserver.

To solve this you have to manually add this line in /etc/hosts after the IPv4 addresses, `<ipv4 address> weirdwebsite.htb`. This way you resolve locally the host and you can actually connect to the website