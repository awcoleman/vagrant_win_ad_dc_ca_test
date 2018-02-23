#=========================================================================

Vagrant file to start Active Directory Domain Controller and Cert Auth

ad			dc01.example.test
linux01
master01

10.123.11.51   master01.example.test master01
10.123.11.101  linux01.example.test linux01
10.123.11.151  dc01.example.test dc01


#=========================================================================

#Get Boxes
vagrant box add mwrock/Windows2012R2 --provider virtualbox   #4.26 GB

vagrant box add centos/7 --provider virtualbox

#Start DC01
vagrant up ad

#This start a WinServer2012R2 box and (in the Vagrantfile provision_ps):
Turns off UAC
Rearms license evaluation period to 180 days
Allows ping
Installs package manager chocolatey
Install sshd
Renames server to DC01
Restarts server

#Connect to DC01 as vagrant user (will ask for password vagrant) and open powershell
vagrant ssh ad
powershell

#Helper Function to retry script block on failure, this takes care of network issues during Windows Update
#https://stackoverflow.com/a/45472343
function Retry-Command {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Position=1, Mandatory=$false)]
        [int]$Maximum = 5
    )

    Begin {
        $cnt = 0
    }

    Process {
        do {
            $cnt++
            try {
                $ScriptBlock.Invoke()
                return
            } catch {
                Write-Error $_.Exception.InnerException.Message -ErrorAction Continue
            }
        } while ($cnt -lt $Maximum)

        # Throw an error after $Maximum unsuccessful invocations. Doesn't need
        # a condition, since the function returns upon successful invocation.
        throw 'Execution failed.'
    }
}

#Install DNS then AD-Domain-Services WindowsFeatures
Retry-Command -ScriptBlock { Install-WindowsFeature DNS -IncludeManagementTools; Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools }

#Create AD domain example.test, will reboot on completion
Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2012R2" -DomainName "example.test" -DomainNetbiosName "EXAMPLE" -ForestMode "Win2012R2" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword (ConvertTo-SecureString "My1Password" -AsPlainText -Force)

#Reconnect
vagrant ssh ad
powershell

#Make vagrant user Domain Admin and Enterprise Admin
$SuperUserGroups = @()
$SuperUserGroups = (Get-ADUser -Identity "Administrator" -Properties * ).MemberOf
ForEach ($Group in $SuperUserGroups ) {
   Add-ADGroupMember -Identity $Group -Members "vagrant"
}

Get-Service adws,kdc,netlogon,dns

#Create 5 sample users:  Myrta Schueller, Emilio Bitton, Tarsha Shain, Lucius Huddleston, Ingrid Krohn
New-ADUser -Name "Myrta Schueller" -GivenName Myrta -Surname Schueller -SamAccountName mschueller -UserPrincipalName "mschueller@example.test" -AccountPassword (ConvertTo-SecureString "Schueller2Password" -AsPlainText -Force) -PassThru | Enable-ADAccount

New-ADUser -Name "Emilio Bitton" -GivenName Emilio -Surname Bitton -SamAccountName ebitton -UserPrincipalName "ebitton@example.test" -AccountPassword (ConvertTo-SecureString "Bitton2Password" -AsPlainText -Force) -PassThru | Enable-ADAccount

New-ADUser -Name "Tarsha Shain" -GivenName Tarsha -Surname Shain -SamAccountName tshain -UserPrincipalName "tshain@example.test" -AccountPassword (ConvertTo-SecureString "Shain2Password" -AsPlainText -Force) -PassThru | Enable-ADAccount

New-ADUser -Name "Lucius Huddleston" -GivenName Lucius -Surname Huddleston -SamAccountName lhuddleston -UserPrincipalName "lhuddleston@example.test" -AccountPassword (ConvertTo-SecureString "Huddleston2Password" -AsPlainText -Force) -PassThru | Enable-ADAccount

New-ADUser -Name "Ingrid Krohn" -GivenName Ingrid -Surname Krohn -SamAccountName ikrohn -UserPrincipalName "ikrohn@example.test" -AccountPassword (ConvertTo-SecureString "Krohn2Password" -AsPlainText -Force) -PassThru | Enable-ADAccount

#Check first and last
Get-ADUser mschueller -properties *
Get-ADUser ikrohn -properties *

#Add HortonworksUsers group
New-ADGroup -Name 'HortonworksUsers' -Description 'Security Group for Hortonworks users' -DisplayName 'Hortonworks Users' -GroupCategory Security -GroupScope Universal -SAMAccountName 'HortonworksUsers' -PassThru

#Add 3 of 5 sample suers to HortonworksUsers group
Add-ADGroupMember -Identity "HortonworksUsers" -Members "mschueller"
Add-ADGroupMember -Identity "HortonworksUsers" -Members "tshain"
Add-ADGroupMember -Identity "HortonworksUsers" -Members "lhuddleston"

#Add ldap bind user for Ambari manager
New-ADUser -Name "svc_hortonworks_ambari" -SamAccountName svchortonworksambari -AccountPassword (ConvertTo-SecureString "Ambari4HDP" -AsPlainText -Force) -PassThru | Enable-ADAccount


#Install Cert Auth
#RE-PASTE Retry-Command from above
Retry-Command -ScriptBlock { Install-WindowsFeature AD-Certificate -IncludeManagementTools }

Install-AdcsCertificationAuthority -CACommonName "Test Root CA" -CAType EnterpriseRootCa -HashAlgorithmName SHA256 -KeyLength 2048 -ValidityPeriod Years -ValidityPeriodUnits 10 -Force

Retry-Command -ScriptBlock { Install-WindowsFeature ADCS-Web-Enrollment }

Install-AdcsWebEnrollment -Force

#Get CA cert to transfer to clients (in ssh/cmd prompt, NOT powershell). DER format.
certutil -ca.cert c:\example_test_root_ca.cer

#=========================================================================

#Now to linux01 (used for basic SSL,LDAP tests, and ansible for master01)
vagrant up linux01
vagrant ssh linux01

sudo yum install -y ansible

#Get CA cert
scp vagrant@dc01:/example_test_root_ca.cer .

#Make a copy in PEM format (from DER)
openssl x509 -inform der -in example_test_root_ca.cer -out example_test_root_ca.pem

#Put copy in central ca store
sudo cp example_test_root_ca.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract

#Check SSL on dc01.example.test:636 
openssl s_client -connect dc01.example.test:636

sudo yum install -y openldap-clients

cat > ~/.ldaprc << "EOF"
HOST dc01.example.test
PORT 636
TLS_CACERT /etc/pki/ca-trust/source/anchors/example_test_root_ca.pem
TLS_REQCERT demand
EOF

#Test ldapsearches
ldapsearch -x -D 'svchortonworksambari@example.test' -w 'Ambari4HDP' -b "dc=example,dc=test" -H 'ldaps://dc01.example.test' sAMAccountName=svchortonworksambari
ldapsearch -x -D 'svchortonworksambari@example.test' -w 'Ambari4HDP' -b "dc=example,dc=test" -H 'ldaps://dc01.example.test' sAMAccountName=ikrohn
ldapsearch -x -D 'svchortonworksambari@example.test' -w 'Ambari4HDP' -b "dc=example,dc=test" -H 'ldaps://dc01.example.test' sAMAccountName=HortonworksUsers

#=========================================================================

#Now to master01
vagrant up master01
vagrant ssh master01

sudo yum install -y wget unzip

#Get CA cert
scp vagrant@dc01:/example_test_root_ca.cer .

#Make a copy in PEM format (from DER)
openssl x509 -inform der -in example_test_root_ca.cer -out example_test_root_ca.pem

#Put copy in central ca store
sudo cp example_test_root_ca.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract


#=========================================================================
#=========================================================================