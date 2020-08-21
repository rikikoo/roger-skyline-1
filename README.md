# roger-skyline-1

roger-skyline-1 is a project about setting up a virtual machine and configuring it to be a (semi-secure) web server.
The network and system configurations are implemented according to given minimum requirements.

The requirements
----

- Install any Linux OS on a hypervisor of your choice
- Give it a disk size of 8 GB, with at least one 4.2 GB partition
- Create one non-root user on the system and have give this user sudo rights.
- Give your machine a static IP address with a 30-bit netmask and disable DHCP.
- Change the default port of the SSH service to a port of your choosing. SSH access has to be done using public keys. Root access via SSH has to be disabled, but allowed for users who can sudo.
- Set up firewall rules for services used outside the VM.
- Set up protection against scans and DOS on all open ports of the machine.
- Create a script that updates all installed packages that runs once a week at 4AM and whenever the machine is rebooted.
- Create a script that sends an email to root if the /etc/crontab file is modified. The task has to be scheduled to run every midnight.
- Stop the services that aren't necessary for this project.


Setting up the VM
----

Install the latest stable release of [VirtualBox](https://virtualbox.org) and download the disk image of Debian 10.2 [(debian-10.2.0-i386-netinst.iso)](https://cdimage.debian.org/debian-cd/current/).

##### IF YOU CHOOSE HOST-ONLY MODE
On VirtualBox
```
File -> Host Network Manager -> Create.
Set Network Mask to 255.255.255.252.
Disable DHCP.
```
Then on the VM's settings
```
Network -> Adapter 1 -> Attached to: Host-Only -> vboxnet0
Adapter 2 -> Enable Network Adapter -> Attached to: NAT
```

##### IF YOU CHOOSE BRIDGED MODE
On VM's settings:
```
Network -> Adapter 1 -> Attached to: Bridged Adapter
```

----

Create a new machine with 1024 MB of RAM and 8 GB virtual disk.

Start the machine and launch the installer. A GUI is not necessary.
During disk partitioning, set up LVM and go with the default values it suggests. Resizing a partition later with `cfdisk` is very simple (at least if the most of the filesystem is mounted as Logical Volumes).


System and network configurations
----

###### CREATING A NON-ROOT USER WITH SUDO RIGHTS
1. Switch to **root** with command `su -` (and typing the root pw when prompted)
2. Create user **faff** (my favorite English word at the time...) with command `adduser faff`
  * come up with a password for the new user, re-enter the password
  * rest of the prompted info is optional (skip 'em)
3. Install `sudo` package in case it hasn't already been installed: `apt-get install sudo`
4. Give **faff** sudo rights with the command `adduser faff sudo`
5. All done! Exit root session simply by typing `exit`


###### INSTALL AND UPDATE THE NECESSARY PACKAGES

First, update all the packages sources with `sudo apt-get update`.
Then update the actual installed packages with `sudo apt-get upgrade`.

Install the necessary packages needed to meet the requirements of the assignment.
- **SSH**: `sudo apt-get install ssh`
- Sending emails using the command line `sudo apt-get install mailutils`
- The firewall tool will be **ufw**. `sudo apt-get install ufw`
- DoS protection is provided by **fail2ban**. `sudo apt-get install fail2ban`
- For extra protection against port scanning: `sudo apt-get install portsentry`
- Web server will be **apache2**. `sudo apt-get install apache2`
- **SSL** tools come with this package `sudo apt-get install openssl`


###### CONFIGURING THE NETWORK INTERFACES

Open the network interface file in `nano` with `sudo nano /etc/network/interfaces`.
Edit it so it contains the following info:
```
# The loopback network interface
auto lo
iface lo inet loopback

# Primary (host-only) network interface
auto enp0s8
iface enp0s8 inet static
	address 192.168.56.2
	netmask 255.255.255.252
	gateway 192.168.56.1
	dns-nameservers 8.8.8.8 8.8.4.4
```

Restart the networking daemon with `sudo systemctl restart networking.service`.

##### NOTE:
- A netmask of /30 is a 30-bit netmask.
  + netmask of /8 = 255.0.0.0 (256 * 256 * 256 available addresses),
  + netmask of /16 = 255.255.0.0 (256 * 256 available addresses),
  + netmask of /24 = 255.255.255.0 (you get the idea),
  + netmask of /32 = 255.255.255.255 (IIRC used if you want the device to be connected only to one other device),
  + netmask of /30 therefore is 2 bits "left" of an "all-1s" byte (255) -> `1111 1100` = 252 -> 3 available addresses in the subnet.

##### NOTE2:
With the host-only connection there is no internet connection available. So if the VM has been set up with a bridged network adapter, the static IP address has to be a valid address on the same subnet as the host. Example:
**Host:** `ifconfig`
```
...

en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400<CHANNEL_IO>
	ether 8c:85:90:35:bc:7f
	inet6 fe80::80b:db0a:d726:ec7a%en0 prefixlen 64 secured scopeid 0x5
	**inet 192.168.1.196 netmask 0xffffff00 broadcast 192.168.1.255**
	inet6 2001:2003:f74c:8700:4c8:4140:99f7:8178 prefixlen 64 optimistic autoconf secured
	inet6 2001:2003:f74c:8700:8cae:8dd5:2797:c085 prefixlen 64 optimistic autoconf temporary
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active

...
```

**Guest:** `sudo nano /etc/network/interfaces`
```
...

auto enp0s3
iface enp0s3 inet static
    address 192.168.1.201
    netmask 255.255.255.252
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
```


###### CONFIGURE SSH

On the _host_ side, create an RSA key-pair with the command `ssh-keygen`.
  - the keys should by default be created to `$HOME/.ssh/id_rsa`and `$HOME/.ssh/id_rsa.pub`.
Upload the public key to the SSH server with the command `ssh-copy-id -i $HOME/.ssh/id_rsa.pub faff@192.168.56.2`.
  - test the connection: `ssh faff@192.168.56.2`.

On the _guest_ side, configure the ssh settings by editing the following lines in the file `/etc/ssh/sshd_config`:
```
#Port 22 -> Port 50607
#PermitRootLogin prohibit-password -> PermitRootLogin no
#PasswordAuthentication yes -> PasswordAuthentication no
```

Restart the SSH daemon for the settings to take effect. `sudo systemctl restart ssh`
Note that logging in to the client via SSH is done by specifying the port: `ssh faff@192.168.56.2 -p 50607`


###### SETTING UP FIREWALL

We want to block all incoming connections except for ports used for HTTP, HTTPS and our custom SSH connections. All incoming traffic is blocked in **ufw** by default, so we just need to allow the three ports mentioned earlier:
`sudo ufw allow 80`
`sudo ufw allow 443`
`sudo ufw allow 50607`

Now all that's left is to enable the firewall: `sudo ufw enable`.
Check that everything's ok with the command `sudo ufw status`. Output should be something like this:
```
Status: active

To          Action      From
--          --          --
80          ALLOW       Anywhere
443         ALLOW       Anywhere
50607       ALLOW       Anywhere
```


###### SETTING UP FAIL2BAN AND IPTABLES CHAIN

Even though **fail2ban** default settings are good enough for this project, some minor changes to the config file are necessary.

First, make a copy of the `jail.conf` file and name it `jail.local`:
`sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`.
Then edit the .local file by changing the default jailed ssh port and enabling the ssh and apache jails:
```
...

[sshd]

# To use aggressive sshd modes...
# ...
#mode   = normal
enabled = true
port    = 50607
logpath = %(sshd_log)s
backend = %(sshd_backend)s

...

[apache-auth]

enabled = true
port    = http,https
logpath = %(apache_access_log)s

...
```

Restart the service for the changes to become active: `sudo systemctl restart fail2ban`.
Check fail2ban status with `sudo fail2ban-client status`.

**iptables** is a linux firewall and is configurable through command lines. I found this config to be effective against for example a _slowloris_ attack:
`iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 50 -j DROP`

- `-A` appends a new _chain_ (a rule)
- `INPUT` is basically incoming traffic
- `-p` specifies the protocol (TCP)
- `--syn` tells to look for SYN packets (used to establish a new connection???)
- `--dport` specifies to look at traffic incoming to port 80
- `-m connlimit` matches the connection limit module
- `--connlimit-above 50` tells to take action if there are over 50 simultaneous connections from the same IP address
- `-j DROP` tells which action to take, in this case dropping the connections that try to connect if there are already 50 connections made to our server.

###### CLOSE OPEN PORTS AND CONFIGURE PORTSENTRY

`netstat -lntup` lists all currently open ports and the process names/IDs that use these ports.
As can be seen, by default portsentry listens to quite many ports. That's fine, even though **ufw** is blocking all incoming traffic.

`sudo nano /etc/portsentry/portsentry.conf` should look something like this:
```
...
# Un-comment these if you are really anal:
#TCP_PORTS="1,7,9,11,15,70,79,80,109,110,111,119,138,139,143,512,513,514,515,540,635,1080,1524,2000,2001,4000,4001,5742,6000,6001,6667,12345,12346,20034,27665,30303,32771,32772,32773,32774,31337,40421,40425,49724,54320"
#UDP_PORTS="1,7,9,66,67,68,69,111,137,138,161,162,474,513,517,518,635,640,641,666,700,2049,31335,27444,34555,32770,32771,32772,32773,32774,31337,54321"
#
# Use these if you just want to be aware:
TCP_PORTS="1,11,15,79,80,111,119,143,443,540,635,1080,1524,2000,5742,6667,12345,12346,20034,27665,31337,32771,32772,32773,32774,40421,49724,50607,54320"
UDP_PORTS="1,7,9,69,161,162,513,635,640,641,700,37444,34555,31335,32770,32771,32772,32773,32774,31337,54321"
#
# Use these for just bare-bones
#TCP_PORTS="1,11,15,110,111,143,540,635,1080,1524,2000,12345,12346,20034,32771,32772,32773,32774,49724,54320"
#UDP_PORTS="1,7,9,69,161,162,513,640,700,32770,32771,32772,32773,32774,31337,54321"
...
```

Then, add the IP address of the host that you use to ssh into your server to `portsentry.ignore.static` file.



###### DISABLING THE SERVICES THAT ARE UNNECESSARY

These are the services enabled on our system:
`sudo systemctl list-unit-files --state=enabled`
```
UNIT FILE                              STATE
apache2.service                        enabled
apparmor.service                       enabled
autovt@.service                        enabled
blk-availability.service               enabled
console-setup.service                  enabled
cron.service                           enabled
dbus-org.freedesktop.timesync1.service enabled
fail2ban.service                       enabled
getty@.service                         enabled
keyboard-setup.service                 enabled
lvm2-monitor.service                   enabled
networking.service                     enabled
rsyslog.service                        enabled
ssh.service                            enabled
sshd.service                           enabled
syslog.service                         enabled
systemd-timesyncd.service              enabled
ufw.service                            enabled
```

apache2, cron, fail2ban, networking, ssh(d) & ufw **obviously** should be enabled.

autovt, console-setup, getty & keyboard-setup are related to the UI's functionality and are AFAIK "safe" or virtually unexploitable. Only thing I found out was that **keyboard-setup** was slowing down some people's server start-up time (by ~5 sec).

systemd-timesyncd & dbus-org.freedesktop.timesync1 need to stay alive. TBH, I didn't look these up. "timesync" just sounds essential in any kind of systems.

(r)syslog obviously is needed for not only checking system logs, but some aforementioned services are also dependent on log activity (fail2ban for example)

lvm2-monitor & blk-availability have something to do with the filesystem, so keeping those alive might be a good idea as well.

apparmor seems to provide some very elementary security against apps and services and packages so they couldn't access absolutely everything in the system, so we'll _definitely_ leave that service running.


In other words, if during debian installation no additional software was selected, all the enabled services can be left running.


Scripts
----

###### PACKAGE UPDATER

Write the script:
`sudo nano $HOME/update_packages.sh`
```
#!/bin/bash

date >> /var/log/update_script.log && \
apt-get update >> /var/log/update_script.log && \
apt-get upgrade >> /var/log/update_script.log
```
`sudo chown root $HOME/update_packages.sh`

Make cron run the script once a week at 4AM and every time the machine is rebooted:
`sudo crontab -e`
```
@reboot /home/faff/update_packages.sh
0 4 * * 1 /home/faff/update_packages.sh
```

Test the script by rebooting the system `sudo systemctl reboot` and checking the log:
`sudo cat /var/log/update_script.log`
The log should look something like this:
```
Mon 03 Feb 2020 05:17:50 PM EET
Hit:1 http://security.debian.org/debian-security buster/updates InRelease
Hit:2 http://deb.debian.org/debian buster InRelease
Get:3 http://deb.debian.org/debian buster-updates InRelease [49.3 kB]
Fetched 49.3 kB in 0s (102 kB/s)
Reading package lists...
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```


###### CRONTAB MONITORING

First, add the task to crontab:
```
0 0 * * * /home/faff/cron_checker.sh
```

Then make a checksum of the crontab file (this needs to be done as root for some reason):
1. `su -`
2. Enter root password
3. `md5sum /etc/crontab > md5cron.txt`
4. `exit`

Finally, create a script that utilizes the checksum. `sudo nano $HOME/cron_checker.sh`
```
#!/bin/bash

md5sum /etc/crontab > /etc/croncheck.txt
diff /etc/croncheck.txt /etc/md5cron.txt > /dev/null 2>&1
error=$?
if [ $error -eq 1 ]
then
	echo "crontab has been modified during the last 24h. Please check logs and remember to make a new checksum of the crontab file and save it to md5cron.txt." | mail -s "cron report" root@localhost
fi
```


Website
----

###### CREATING A SELF-SIGNED SSL CERTIFICATE

Follow [these 3rd party instructions](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-16-04).
In short,
1. `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt`
2. Make a backup of the Apache SSL Virtual Host config file
3. Edit the `default-ssl.conf` so it knows to use the self-signed certificate we just created
4. Enable the changes made to Apache
  - `sudo a2ensite default-ssl`
  - `sudo a2enmod ssl`
5. Reload Apache `sudo systemctl reload apache2`


###### FRONT-END OF THE WEBSITE

Make a backup of the default _It works!_ index file. `sudo cp /var/www/html/index.html /var/www/html/index.html.bak`

Modify the index.html file however you wish. Here's mine:
```
TBD
```


Conclusion
----

Many things were copied almost "as-is" from teh interwebz, since they seemed to be doing what was required by the subject of the assignment.

I did spend **a lot** of time studying the topics related (and sometimes not directly related) to this project... too much actually. Most people completed this project in two-three weeks, when it took me five.

I felt comfortable explaining my choices at the time of submitting my work for peer-evaluation, but I honestly could not have done even a fraction of the requirements without many step-by-step instructions found on SuperUser, ServerFault, StackOverflow and various other blogs etc.

All in all, I don't regret using so much time studying the field of IT administration, but it's clear to me now that most of the learning happened when I actually tried modifying the various config files and seeing what happens. Most of the stuff that I read during this project I've already forgotten. So if anything, I now know that I need to dive straight in to the trial-and-error method when learning new stuff.

Also a big thanks to [a fellow Hiver](https://github.com/vkuokka) who shared a couple _keywords_ I should google when I was stuck at the beginning.
