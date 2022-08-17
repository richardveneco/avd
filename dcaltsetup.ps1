$domain3 =  Get-ADForest | Select-Object -ExpandProperty name
$DistinguishedName = Get-ADDomain | foreach{$_.DistinguishedName}
$CustomerOU = "OU=Company" + ", " + $DistinguishedName
$netbiosname = Get-ADDomain | foreach{$_.NetBIOSName}


Import-Module ADDSDeployment,ServerManager,activedirectory
Add-DnsServerForwarder -IPAddress '8.8.4.4,8.8.4.4' -PassThru

Import-Module ServerManager 
Add-WindowsFeature SMTP-Server,Web-Mgmt-Console,WEB-WMI
$virtualSMTPServer = Get-WmiObject IISSmtpServerSetting -namespace “ROOT\MicrosoftIISv2” | Where-Object { $_.name -like “SmtpSVC/1” }
$virtualSMTPServer.FullyQualifiedDomainName = $domeinNaam
$virtualSMTPServer.SmartHost = "webmail.myeasyoffice.nl"
$virtualSMTPServer.MaxMessageSize = "262144000"
$virtualSMTPServer.MaxBatchedMessages = "300"
$virtualSMTPServer.MaxRecipients = "1000"
$virtualSMTPServer.MaxSessionSize = "262144000"
$virtualSMTPServer.SmartHostType = "2"
$virtualSMTPServer.Put()
Set-Service -Name "SMTPSVC" -StartupType Automatic
Restart-Service "SMTPSVC"

Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $domain3 -Confirm:$false

New-ADOrganizationalUnit "Company" -Path $DistinguishedName
New-ADOrganizationalUnit "Beveiligingsgroepen" -Path $CustomerOU
New-ADOrganizationalUnit "Gebruikers" -Path $CustomerOU
New-ADOrganizationalUnit "Database Server" -Path $CustomerOU
New-ADOrganizationalUnit "Terminal Server" -Path $CustomerOU
New-ADOrganizationalUnit "Service Accounts" -Path $CustomerOU
New-ADOrganizationalUnit "Mailboxen" -Path $CustomerOU
New-ADOrganizationalUnit "Beperkte Gebruikers" -Path $CustomerOU

New-ADGroup -Name "Werkplek Inloggroep" -description "Toegang tot Azure Virtual Desktop" -Path "OU=Beveiligingsgroepen,$CustomerOU" -GroupScope Global
New-ADGroup -Name "SQL Inloggroep" -Path "OU=Beveiligingsgroepen,$CustomerOU" -GroupScope Global

takeown /f C:\Windows\PolicyDefinitions  /a /r /d y
icacls.exe C:\Windows\PolicyDefinitions /grant "administrators:F" /t /c /q
icacls.exe C:\Windows\PolicyDefinitions /grant "System:(OI)(CI)F" /t /c /q
# Copy-Item -Force "$provisioningPubShare\PolicyDefinitions\*.admx" C:\Windows\PolicyDefinitions 
# Copy-Item -Force "$provisioningPubShare\PolicyDefinitions\en-US\*.adml" C:\Windows\PolicyDefinitions\en-US
icacls.exe C:\Windows\PolicyDefinitions /setowner "NT SERVICE\TrustedInstaller" /t /c /q

New-Item "C:\Shares\Resources"-ItemType directory
New-SMBShare -Name "Resources$" -Path "C:\Shares\Resources" -FullAccess ("Administrators") -ChangeAccess ("Werkplek Inloggroep") -FolderEnumerationMode AccessBased
$Path = "C:\Shares\Resources"
$Acl = Get-Acl $Path
$Acl.SetAccessRuleProtection($True, $False)
$AclIedereen = New-Object system.security.accesscontrol.filesystemaccessrule("EVERYONE","ReadandExecute","Allow")
$Acl.SetAccessRule($ACLIedereen)
$AclAdministrators = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$Acl.SetAccessRule($AclAdministrators)
Set-ACL -Path $Path $Acl
