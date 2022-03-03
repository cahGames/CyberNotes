<ins>Linux Privilege Escalation</ins>:

- *Enumeration*:
    - LinEnum (https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh), simple bash script that performs common commands to detect privilege escalation vulnerabilities
        - output sections of the command:
            - kernel: shows information about kernel and its vulnerabilities
            - world-writable files: used to detect misconfigurations that allows to find sensitive writable files
            - SUID files: files that have the SETUID bit set. The command that LinEnum runs is `find / -perm -u=s -type f 2>/dev/null`
            - Crontab Contents: shows the scheduled cron jobs
    - LinPEAS (https://github.com/ozonett/privilege-escalation-awesome-scripts-suite)
        - more easier to read than LinEnum
    - sometimes users may type passwords on the command line, so it's a good think to check history files using `cat ~/.*history`
    - config files can also reveal plaintext passwords
- *Exploitation*:
    - **Writable /etc/passwd file**: to exploit this we can just create a new root user account by adding a line to the file
        1.  first we create a password hash, using the command `openssl passwd -1 -salt <salt> <password>`
        2.  then we just add the line `<username>:<passwordhash>:0:0:root:/root:/bin/bash` or replace the root's password field with the hash
    - **Readable /etc/shadow file**: we can exploit this by trying to crack the password hashes contained in the file
    - **Writable /etc/shadow file**: this is even simpler, since we can just replace root password
        - we can generate a new password hash with this command: `mkpasswd -m sha-512 password`
    - **sudo misconfigurations**:
        1.  run the command `sudo -l`
        2.  If there are any commands you can execute as root, look for a way to get privilege escalation with those commands (this is a good place to start: https://gtfobins.github.io/)
        3.  There may be some enviromental variables that are inherited when a sudo command is run. That may be exploitable
    - **/etc/crontabs misconfigurations**:
        - sometimes there may be cron jobs that let root execute files we can write. We can modify the file with shellcode to get a shell with root permissions.
        - look for enviromental variables defined in the file, especially for PATH
    - **SUID/SGID Executables**: these are files you can execute as root. These files may contain some vulnerabilities:
        - **Shared Object Injection**: happens when the binary tries to import a shared object (.so file) from a directory writable to us.
            1.  run the command `strace ./path/to/suid 2>&1 | grep -iE "open|access|no such file"` to find the paths of the shared objects the executable imports
            2.  replace the file with one that spawns a shell (TODO: explain how)
        - **PATH variable exploitation**: sometimes we have a SUID binary that executes commands like ps without indicating their absolute path. To exploit this we:
            1.  find the command that the program runs, using commands like `strings`. For example, let's say we have a binary that executes `ls`.
            2.  move in a directory writable to us and write the shellcode in a file named `ls` .
            3.  <ins>make the file executable</ins>
            4.  change the PATH variable so that it points to the directory where we just created our shellcode file. To do that we use the command `export PATH=/<absolute_path_to_our_directory>:$PATH`
            5.  execute the binary
        - **Bash functions exploitation** (only for bash versions <4.2-048): if we have a SUID binary that executes another executable using the absolute path, we can still exploit this:
            1.  check the bash version with `/bin/bash --version`
            2.  identify the path of the executable the SUID binary calls during its execution.
            3.  create a bash function using `function /path_to_executable { /bin/bash -p; }` and export it using `export -f /path_to_executable`
            4.  run the SUID binary
        - **Bash in debugging mode** (only for bash versions <4.4):
            1.  run `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2`
            2.  run `/tmp/rootbash -p`
    - **Vulnerable NFS share**: check the NFS section in this page
    - **Kernel exploits**: they can leave the system in an unstable state, use them as last resort
- useful links and tools:
    - checklists ([https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Linux - Privilege Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md))
    - https://github.com/jondonas/linux-exploit-suggester-2, useful to find kernel exploits

<ins>Enviromental Variables</ins>:

- you can execute the command `env` to see all the variables
- to get the value of a specific variable use `echo $VARIABLE`
- to set the value of a new/existing variable use `export VARIABLE=value`
- here are the most important default env variables:
    - PATH: specifies one or more directories (separated by a colon) that hold executable programs. When a generic command like `ls` or `cat` wants to be executed in a terminal or in a script, these directories are checked to see if the respective executable exists

<ins>Important files</ins>:

- `/etc/passwd`: readable by everyone (by default) and contains user account information. Every line contains 7 fields (separated by a colon) that describe a user:
    - Username
    - Password: usually is an x, to indicate it's encrypted and stored in the /etc/shadow file. But it can also be an hash!
    - User ID (UID)
    - Group ID (GID)
    - User ID Info: contains extra information about the user such as phone number, mail etc.
    - Home directory
    - Command/shell: the absolute path of a command or shell (usually it's a shell)
- Crontabs (located in `/etc/crontab`): one-time/recurring tasks executed by the Cron daemon. The format of a cron job is explained particularly well in the file

<ins>Important commands</ins>: (https://explainshell.com/ is an EXTREMELY useful site)

- `locate` to quickly find a file by its name