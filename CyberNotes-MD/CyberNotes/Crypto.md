- How to calculate n-th root for big numbers?

If you want to use python, standard operations can't handle numbers that are too big. Instead you have to use a library called decimal. Here is an example:

```Python
import decimal

decimal.getcontext().prec=3000 #keep this number high otherwise the numbers could get truncated
n = 225733570376365932468335996375485440054093549241953232419102010172016315697547410301618526179816207849388202337216300099060281594319157047118340810842614980739142593719403296503190159366855910150443967239048692403018881883298092411312981364586682701412197994716892488377726541494395803924293481584332850923331357006872822703511471333914818558324398192361564633112331754181874133385540953940688236229294427707563453263917943449756776327030220639468992996789681805763314662158584093477410079443060019776340638009624431171614377622399628875116341442101
d = decimal.Decimal(str(n))
r = d ** (decimal.Decimal('1') / 3)
print(r)
```

<ins>GPG</ins>: open source implementation of PGP (pretty good privacy)

<ins>RSA Vulnerabilities</ins>:

- useful links and tools:
    - https://github.com/Ganapati/RsaCtfTool  (not the best to learn things, but it lists a bunch of vulnerabilities)
    - https://github.com/ius/rsatool

<ins>Hash function</ins>:

- one way mathematical function that takes in input a string and converts (or digests) it into a fixed size string (called hash).
- hashing algorithms are relatively fast to compute, but very slow to reverse
- hashing functions are used to verify integrity of data or for verifying passwords
    - when storing a password, it should be hashed and *salted*. A salt is a random string that you store with the user's ID and mix into the password when you compute the hash. This way, even if two users choose the same password, their salts will be different, and they'll end up with different hashes.
    - the integrity and authenticity of data can be verified with HMAC
- *rainbow table*: lookup table of hashes to plaintexts. If it's sorted, searching for a hash becomes really fast. NOTE: This is useless against salting!
- hashes can have a prefix that identifies its hashing algorithm
- useful links and tools:
    - https://pypi.org/project/hashID/  to recognize the type of hash (however, it's reliable only for the hashes that have a prefix)
    - https://hashcat.net/wiki/doku.php?id=example_hashes  to see all the types of hashes

<ins>How to crack a hash:</ins>

You can do what's called a **dictonary attack** by using John The Ripper, using this command:

`john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256 hash.txt`

- `--format` is optional, if it's omitted John will try to find the correct format automatically (not always reliable, use an hash identifier for weird hashes)
- use the command `john --list=formats` to get a list of all the hash types John supports
- if no wordlist is provided, john will first try to use its default wordlist (`/usr/share/john/password.lst`), and then it will proceed with the incremental ASCII mode. This can take centuries, so it's not recommended unless you know that the plaintext is really short
- **Single Crack Mode**: if the `--single` option is set, John is provided with only a password, and tries to work out possible passwords using a technique called **word mangling**.
    - NOTE: the file you have to provide can't contain only a hash, but also a username that allows john to create a custom wordlist based on that.
        Example:
        `mike:1efee03cdcb96d90ad48ccc7b8666033`
        By running `john --single --format=Raw-MD5 hash.txt`, john will try passwords like M1ke, MIke, mik3, etc.
- **Cracking a Password Protected Zip File:** to do that we need to extract the hashed password from the zip file. We can do that using this simple command (included with john): `zip2john zipfile.zip > zip_hash.txt`
    Once we've done that we have a hash we can try to crack.
- **Cracking a Password Protected RAR Archive:** identical to the above procedure, but to extract the hash of the archive we need this command: `rar2john rarfile.rar > rar_hash.txt`
    Once we've done that we have a hash we can try to crack.
- **Cracking SSH Keys Passwords:** a private SSH key can be protected with a password. We can extract its hash using `python3 /usr/share/john/ssh2john.py id_rsa > hash.txt` (if you're using Kali)
- to crack the `/etc/shadow` file (the file that contains all the hashed passwords of users and other info), we can first use a command called unshadow (already included with john). The basic command is:
    `unshadow /etc/passwd /etc/shadow > unshadowed.txt`
    - of course you can make a copy of passwd and shadow and provide the paths to those copies
    - unshadow "combines" the two files
    - we can the feed the output from unshadow directly into john, with the option `--format=sha512crypt`
- Custom Rules: you can create custom rules in the file `/etc/john/john.conf` that can be used along with wordlists using the option `--rule=rule_name`
    For more info: https://www.openwall.com/john/doc/RULES.shtml

*Alternatives*:

- https://crackstation.net/ , useful to easily crack weak password hashes