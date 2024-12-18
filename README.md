# UpdateDDNS
Update DNS-O-Matic and NameCheap Dynamic DNS

**Usage:**    
    UpdateDDNS.ps1 [-C[onfigFile] '*path/to/config/file*'] [-Force] [-UpdatePassword]

-ConfigFile: specify a custom configuration file. By default this is the name of the script file with a '.json' extension in the script directory.

-Force: Force the update even if the public IP address hasn't changed.

-UpdatePassword: Prompt for updated passwords for accounts and save to config file as encrypted secure strings

Updated to use JSON config file, save current Public IP address to config file instead of environmental variable. Renamed some functions. No option to email log file at present.
