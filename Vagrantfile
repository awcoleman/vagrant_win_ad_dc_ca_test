$provision_ps = <<SCRIPT
REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /f /v EnableLUA /t REG_DWORD /d 0
iex "$env:windir\\system32\\cscript.exe $env:windir\\system32\\slmgr.vbs /rearm"
Import-Module NetSecurity
New-NetFirewallRule -Name Allow_Ping -DisplayName "Allow Ping"  -Description "Allow ICMPv4 echo" -Protocol ICMPv4 -IcmpType 8 -Enabled True -Profile Any -Action Allow
iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
choco install openssh -params '"/SSHServerFeature"' -y
Rename-Computer -NewName "DC01"
Restart-Computer
SCRIPT

$provision_centos = <<SCRIPT
#!/bin/bash
set -xe
sed -i -e "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
systemctl restart sshd
ifup eth1
cat > /etc/hosts <<"EOF"
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
10.123.11.51   master01.example.test master01
10.123.11.101  linux01.example.test linux01
10.123.11.151  dc01.example.test dc01
EOF
SCRIPT

Vagrant.configure("2") do |config|
	config.ssh.insert_key=false
	
    config.vm.define "ad" do |ad|
		ad.vm.network "private_network",ip: "10.123.11.151"
		ad.vm.box = "mwrock/Windows2012R2"
		ad.vm.provision "shell", inline: $provision_ps
	end
	
	config.vm.define "linux01" do |linux01|
		linux01.vm.hostname="linux01.example.test"
		linux01.vm.network "private_network",ip: "10.123.11.101"
		linux01.vm.box = "centos/7"
		linux01.vm.provision "shell", inline: $provision_centos
	end
	
	# Ambari + Master + Worker
	config.vm.define "master01" do |master01|
		master01.vm.hostname = "master01.example.test"
		master01.vm.network "private_network", ip: "10.123.11.51"
		master01.vm.box = "centos/7"
		master01.vm.provision "shell", inline: $provision_centos
		master01.vm.provider "virtualbox" do |vb|
			vb.memory = "4096"
		end
		master01.vm.network "forwarded_port", guest: 8080, host: 8080, auto_correct: true
		master01.vm.network "forwarded_port", guest: 8088, host: 8088, auto_correct: true
		master01.vm.network "forwarded_port", guest: 18080, host: 18080, auto_correct: true
	end
	
end
