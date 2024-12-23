#Requires -Version 7.0
# UpdateDDNS.ps1 
# Update Dynamic DNS on DNSOMatic.com via HTTP GET request.
# Adapted from https://gist.github.com/efigueroa/f9493c3c98c3013177b7
# To update a password, run this from the PS prompt:
#    "newpassword" | ConvertTo-Securestring -AsPlainText -Force | ConvertFrom-SecureString
Param(
	[Alias("c")]
	[string]$ConfigFile = $(Join-Path -Path $(Split-Path $PSCommandPath) -ChildPath "$((Get-Item $PSCommandPath).BaseName).json"),
	[switch]$UpdatePassword = $false, # Prompt for an updated password
	[switch]$Force # Force update even if it hasn't changed
	
	
)

# Get the contents of a JSON file
function Get-JsonFileContents {
	param (
	  [string]$Path
	)
  
	$json = Get-Content -Path $Path -Raw
	$jsonObject = ConvertFrom-Json -InputObject $json
	return $jsonObject
  }

# Write a message to log.
function Add-LogMessage ($MSG) {
	$script:Logger += "$(get-date -format u) $MSG`n"
	Write-Output $MSG
}

# Write an error to log.
function Add-LogError ($MSG) {
	$script:Logger += "$(get-date -format u) ERROR`: $MSG`n"
	Write-Error "ERROR`: $MSG"
}

# Write contents of log to file.
function Flush-Log {
	Add-Content -Path $LogFile -Value $script:Logger
}

# Update the credentials for DNSOMatic
function Update-Password{
	Add-LogMessage "Updating password"
	Add-LogMessage "Loading configuration file: $ConfigFile"
	$config = Get-JsonFileContents -Path $ConfigFile
	while (($choice.Length -ne 1) -and ("DNB" -notcontains $choice)) {
		$choice = Read-Host "Update [D]NS-O-Matic, [N]amecheap, or [B]oth?"
	}
	if (($choice -eq "D") -or ($choice -eq "B")) {
		$password = Read-Host -AsSecureString "Enter DNS-O-Matic password"
		$passwordEncrypted = $password | ConvertFrom-SecureString
		Update-ObjectMember -Object $config -Name "DNSOPassword" -Value $passwordEncrypted
	}
	if (($choice -eq "N") -or ($choice -eq "B")) {
		$password = Read-Host -AsSecureString "Enter NameCheap password"
		$passwordEncrypted = $password | ConvertFrom-SecureString
		Update-ObjectMember -Object $config -Name "NameCheapPassword" -Value $passwordEncrypted
	}
	

	$config | ConvertTo-Json | Out-File -FilePath $ConfigFile
	Exit
}

# Update PSCustomObject member
function Update-ObjectMember {
	param (
		[PSCustomObject]$Object,
		[string]$Name,
		[string]$Value
	)
	if (!($Object."$Name")) {
		$Object | Add-Member -MemberType NoteProperty -Name $Name -Value ''
	}
	$Object."$Name" = $Value
}

# Start script
# Define log file path
$LogFile = Join-Path -Path $(Split-Path $PSCommandPath) -ChildPath "$((Get-Item $PSCommandPath).BaseName).log"
# Limit to Trim large log file
$LogFileMaxLines = 10000
# URI to get public IP from
$PublicIPURI = 'http://myip.dnsomatic.com/'

try {
	if ($UpdatePassword) {
		Update-Password
	}
	$Logger = ""
	if (Test-Path $LogFile) {
		(Get-Content $LogFile -tail $LogFileMaxLines -readcount 0) | set-content $LogFile 
	}
	Add-LogMessage "==============================================="
	Add-LogMessage "Starting Dynamic DNS Update Client"
	if ($Force) {
		Add-LogMessage "-Force option applied."
	}

	# Check if a config file exists.
	Add-LogMessage "Looking for a configuration file: $ConfigFile"
	if (!(Test-Path -path $ConfigFile)) {
		Add-LogError "A valid configuration file could not be found"
		exit 1
	}
	# Load configuration:
	Add-LogMessage "Parsing $ConfigFile"
	$config = Get-JsonFileContents $ConfigFile
	if ($config.Count -eq 0) {
		Add-LogError "The file $ConfigFile didn't have any valid settings"
		exit 2
	}
	
	# Get current public IP address
	$IPpattern   = '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
	Add-LogMessage "Retrieving public IP address from $PublicIPURI."
	$CurrentIp = Invoke-RestMethod -UseBasicParsing -Uri $PublicIPURI
	if (!($CurrentIp -match $IPPattern)) {
		Add-LogError "A valid public IP address could not be retrieved"
		exit 3
	}
	$StoredIp = $config.StoredIp
	Add-LogMessage "Stored IP: '$StoredIp' Retrieved IP: '$CurrentIp'"
	# Compare current IP address with environment variable.	 
	if ($Force) {
		Add-LogMessage "Forcing update."
	} else {
		if ($StoredIp -eq $CurrentIp ) {
			Add-LogMessage "No update required"
			exit 0
		}
	}
	
	Add-LogMessage "Updating IP address on DNS-O-Matic"
	# See https://www.dnsomatic.com/docs/api
	# https://updates.dnsomatic.com/nic/update?hostname=[HOSTNAME]&myip=[IP]&wildcard=NOCHG&mx=NOCHG&backmx=NOCHG
	$Hostname		= $config.DNSOHostname
	$DDNSUsername   = $config.DNSOUsername
	$DDNSPassword  	= ConvertTo-SecureString $config.DNSOPassword
	$UpdateUrl     	= "https://updates.dnsomatic.com/nic/update?hostname=$Hostname&myip=$CurrentIp&wildcard=NOCHG&mx=NOCHG&backmx=NOCHG"
	$cred 			= New-Object System.Management.Automation.PSCredential($DDNSUsername, $DDNSPassword)
	$response 		= Invoke-WebRequest -Uri $UpdateUrl -Method Get -Authentication Basic -Credential $cred
	Add-LogMessage "DDNS Response: $response"
	Add-LogMessage "DDNS Updated at dnsomatic.com"

	Add-LogMessage "Updating IP address on NameCheap"
	# See https://www.namecheap.com/support/knowledgebase/article.aspx/29/11/how-to-dynamically-update-the-hosts-ip-with-an-https-request/
	# https://dynamicdns.park-your-domain.com/update?host=[host]&domain=[domain_name]&password=[ddns_password]&ip=[your_ip]
	$Hostname		= $config.NameCheapHostname
	$DDNSDomain   	= $config.NameCheapDomainName
	$DDNSPassword  	= ConvertTo-SecureString $config.NameCheapPassword
	$DDNSPassword	= (New-Object PSCredential 0, $DDNSPassword).GetNetworkCredential().Password
	$UpdateUrl     	= "https://dynamicdns.park-your-domain.com/update?host=$Hostname&domain=$DDNSDomain&password=$DDNSPassword&ip=$CurrentIp"
	$response 		= Invoke-WebRequest -Uri $UpdateUrl -Method Get
	Add-LogMessage "DDNS Response: `r`n $response"
	Add-LogMessage "DDNS Updated at NameCheap"
	
	Add-LogMessage "Updating stored IP address"
	Update-ObjectMember -Object $config -Name "StoredIp" -Value $CurrentIp
	Add-LogMessage "End of script"
	$config | ConvertTo-Json | Out-File -FilePath $ConfigFile
}
catch [System.Exception] {
	Add-LogError $_.Exception.Message
	exit 5
}
finally {
	Flush-Log
}
