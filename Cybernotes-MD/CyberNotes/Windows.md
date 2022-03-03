<ins>Active Directory:</ins>

- what is Active directory?
    1.  directory service
    2.  distributed, hierarchical database structure that contains information for locating, securing, managing and organizing computer and network resources (a.k.a. files, users, groups, network devices etc.).
        This database is also called **AD DS Data Store**, and it's located in the `%SystemRoot%\NTDS` directory (it's the ntds.dit file)
    3.  something to control a Windows network
- Components:
    - **Domain Controller**: Windows server that handles
        - storing the AD DS data store
        - authentication and authorization services
        - replicate updates from other domain controllers
        - allows admin access to manage domain resources
    - **Organizational Units** (OUs): containers for groups, computers, users, devices and other OUs.
    - **Users**: there are four main types of users (but there could be more, depending on the network)
        - Domain Admins: they control the domains, and are the only ones with access to the domain controller
        - Service Accounts: they handle service maintenance. They can be domain admins.
        - Local Administrators: they can make changes to local machines as an administrator (including managing users of the machine), but they can't access the domain controller
        - Domain Users: normal users that have authorization to access the machines and do things.
    - **Groups**: groups are used so it's easier to organize users and objects. There are two types of AD groups
        - Security Groups: used to specify permissions for a large number of users
        - Distribution Groups: used to specify email distribution lists (an attacker could need this for enumeration purposes)
    - **Trusts**: mechanism for users in the network to gain access to other resources in the domain. There are two types of trusts
        - Directional: the trust includes only 2 domains
        - Transitive: the trust includes more than 2 domains
    - **Policies**: rules that describe how the network operates
        - Group Policy Objects (GPOs): policies that are applied just for a specific set of groups
    - **Domain Services**: services the domain controller provides to the rest of the domain or tree. These are the main access point for attackers. The default domain services are:
        - LDAP: provides communication between applications and directory services
        - Certificate Services: allows the domain controller to handle public key certificates
        - DNS, LLMNR, NBT-NS: Domain Name Services
- Active Directory Forest:
    - collection of one or more domain trees inside an AD network
- There are two types of Active Directory:
    - On-Premise Active Directory (AD)
        - physical Active Directory network
        - uses these authentication protocols: NTLM, LDAP/LDAPS, KERBEROS
    - Azure Active Directory (AAD)
        - cloud Active Directory network, used for online applications (like Microsoft Cloud services)
        - Azure acts as a middle man between the physical AD and the users. This makes the network more secure.
        - uses these authentication protocols: SAML, OAUTH 2.0, OpenID Connect

<ins>Windows privilege escalation</ins>:

- PowerUp script (https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
    - import it using `. .\PowerUp.ps1`
    - `Invoke-AllChecks`

<ins>Powershell:</ins>

- Execution Policy: safety feature that controls the conditions under which PowerShell loads configuration files and runs scripts.
    To bypass this run in cmd the command `powershell -ep bypass`
- Basic commands
    - dot-source operator: used to import script files in the current session of ps. Example: `. .\evilscript.ps1`
    - `cat` or `type`: the equivalent of 'cat' in Linux
    - `icacls`: command to check permissions on a file/folder
- useful links and tools:
    - PowerView, tool to gain network situational awareness on Windows Domains (https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon).
        And also, https://www.hackingarticles.in/active-directory-enumeration-powerview/

<ins>Administration Utility Tools</ins>: these are tools used by administrators to configure a windows pc

- Computer management
- Local Security Policy: used to configure security settings like minimum password length, enabling/disabling guest or local administrator accounts etc.
    - if the computer is not integrated in an Active Directory enviroment, disabling local administrator account is a bad idea
- Disk Cleanup
- Registry Editor