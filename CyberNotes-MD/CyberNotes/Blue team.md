<ins>Cyber deception</ins>: ways to make hackers waste their time when they try to hack your network

NOTE: these techniques are useless (and some of them are probably illegal) to use in Attack/Defense competitions

- **Honeypots**: a network intended to mimic likely targets of cyberattacks, used to detect attacks or deflect them from a legitimate target
- **Canary Tokens**: (canarytokens.org)
    - in short, *something* that triggers a notification when a potentially malicious actions is done by an attacker
- **Port spoofing**: (https://drk1wi.github.io/portspoof/)
    - technique that aims to make attackers waste a LOT of time when trying to scan ports on a machine
    - Portspoof listens on a single port (default one is 4444), but the machine is configured so that every incoming connection is redirected to that port.
        This allows Portspoof to respond on any port, and when an attacker runs nmap on the machine, all ports are reported as open.
- **Honey User Account**:
    - user that triggers an event when somebody tries to access it.
- **Honeybadger**: (https://github.com/adhdproject/honeybadger)
    - powerful Active Defense tool to determine the location of an attacker
        - using IP geolocation
        - using Wireless Survey (a.k.a. the list of wifi networks you can connect to!)
- useful links:
    - https://engage.mitre.org/matrix/