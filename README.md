<div align="center">
  <img src="https://raw.githubusercontent.com/dbernaci/CIS-Debian10-Ansible/master/files/header.png">
</div>


Ansible CIS Debian 10 Hardening [![Build Status](https://travis-ci.com/dbernaci/CIS-Debian10-Ansible.svg?branch=main)](https://travis-ci.com/dbernaci/CIS-Debian10-Ansible)
=========

Configure Debian 10 machine to be [CIS](https://www.cisecurity.org/cis-benchmarks/) compliant. 

Note: this role will make changes to the system that could break things. This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

CIS hardened Debian: cyber attack and malware prevention for mission-critical systems
CIS benchmarks lock down your systems by removing:
1. non-secure programs.
2. disabling unused filesystems.
3. disabling unnecessary ports or services.
4. auditing privileged operations.
5. restricting administrative privileges.


CIS benchmark recommendations are adopted in virtual machines in public and private clouds. They are also used to secure on-premises deployments. For some industries, hardening a system against a publicly known standard is a criteria auditors look for. CIS benchmarks are often a system hardening choice recommended by auditors for industries requiring PCI-DSS and HIPPA compliance, such as banking, telecommunications and healthcare.
If you are attempting to obtain compliance against an industry-accepted security standard, like PCI DSS, APRA or ISO 27001, then you need to demonstrate that you have applied documented hardening standards against all systems within the scope of assessment.


The Debian CIS benchmarks are organised into different profiles, namely **‘Level 1’** and **‘Level 2’** intended for server and workstation environments.


**A Level 1 profile** is intended to be a practical and prudent way to secure a system without too much performance impact.
* Disabling unneeded filesystems,
* Restricting user permissions to files and directories,
* Disabling unneeded services.
* Configuring network firewalls.

**A Level 2 profile** is used where security is considered very important and it may have a negative impact on the performance of the system.
* Creating separate partitions,
* Auditing privileged operations

The Debian CIS hardening tool allows you to select the desired level of hardening against a profile (Level1 or Level 2) and the work environment (server or workstation) for a system.
For example:
```Bash
ansible-playbook -i inventory cis-Debian-20.yaml --tags="level_1_server"
```
You can list all tags by running the below command:
```Bash
ansible-playbook -i host run.yaml --list-tags
```


Based on
```Text
CIS Debian Linux 10 Benchmark
v1.0.0 - 02-13-2020
```


**Check Example dir**
_________________


Requirements
------------

You should carefully read through the tasks to make sure these changes will not break your systems before running this playbook.

You can download Free CIS Benchmark book from this URL
[Free Benchmark](https://learn.cisecurity.org/benchmarks)


To start working in this Role you just need to install Ansible.
[Installing Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)


_________________

Role Variables
--------------

You have to review all default configuration before running this playbook, there are many role variables defined in defaults/main.yml.

* If you are considering applying this role to any servers, you should have a basic familiarity with the CIS Benchmark and an appreciation for the impact that it may have on a system.
* Read and change configurable default values.

Examples of config that should be immediately considered for exclusion:

**5.2.18 Ensure SSH access is limited**, which by default effectively limit access to the host (including via ssh).

**For example:**

* CIS-Debian10-Ansible/defaults/main.yml
```YAML

#Section 5
# 5.2.18 Ensure SSH access is limited
allowed_users: pippo #Put None or list of users space between each user

```

Also consider skipping tag 1.1.1.7 (Ensure mounting of FAT filesystems is limited): the FAT filesystem format is used by UEFI systems for the EFI boot partition.

If you need you to change file templates, you can find it under `templates/*` directory
If you need to change banner, edit banner file in `files/*` directory

_________________

Dependencies
------------

* Ansible version >= 2.9

_________________

Example Playbook
----------------

Below an example of a playbook

```Yaml
---
- hosts: host1
  become: yes
  remote_user: root
  gather_facts: yes
  roles:
    - { role: "CIS-Debian10-Ansible",}
```

### Run all
If you want to run all tags use the below command:
```Bash
ansible-playbook -i [inventoryfile] [playbook].yaml
```
### Dry Run 
```Bash
ansible-playbook -i host -C playbook.yaml 
```
### Run specfic section
```Bash
ansible-playbook -i host playbook.yaml -t section2
```
### Run multi sections
```Bash
ansible-playbook -i host playbook.yaml -t section2 -t 6.1.1
```
* Note:
When run an individual task be sure from the dependencies between tasks, for example, if you run tag **4.1.1.2 Ensure auditd service is enabled** before running **4.1.1.1 Ensure auditd is installed** you will get an error at the run time.





_________________


## Table of Roles:

 **1 Initial Setup**
  - 1.1 Filesystem Configuration
  - 1.1.1 Disable unused filesystems
  - 1.1.1.1 Ensure mounting of freevxfs filesystems is disabled (Scored)
  - 1.1.1.2 Ensure mounting of jffs2 filesystems is disabled (Scored)
  - 1.1.1.3 Ensure mounting of hfs filesystems is disabled (Scored)
  - 1.1.1.4 Ensure mounting of hfsplus filesystems is disabled (Scored)
  - 1.1.1.5 Ensure mounting of squashfs filesystems is disabled (Scored)
  - 1.1.1.6 Ensure mounting of udf filesystems is disabled (Scored)
  - 1.1.1.7 Ensure mounting of FAT filesystems is limited (Not Scored)
  - 1.1.2 Ensure /tmp is configured (Scored)
  - 1.1.3 Ensure nodev option set on /tmp partition (Scored)
  - 1.1.4 Ensure nosuid option set on /tmp partition (Scored)
  - 1.1.5 Ensure noexec option set on /tmp partition (Scored)
  - 1.1.6 Ensure separate partition exists for /var (Scored).
  - 1.1.7 Ensure separate partition exists for /var/tmp (Scored)
  - 1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
  - 1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
  - 1.1.10 Ensure noexec option set on /var/tmp partition (Scored)
  - 1.1.11 Ensure separate partition exists for /var/log (Scored)
  - 1.1.12 Ensure separate partition exists for /var/log/audit (Scored)
  - 1.1.13 Ensure separate partition exists for /home (Scored)
  - 1.1.14 Ensure nodev option set on /home partition (Scored)
  - 1.1.15 Ensure nodev option set on /dev/shm partition (Scored)
  - 1.1.16 Ensure nosuid option set on /dev/shm partition (Scored)
  - 1.1.17 Ensure noexec option set on /dev/shm partition (Scored)
  - 1.1.18 Ensure nodev option set on removable media partitions (Not Scored)
  - 1.1.19 Ensure nosuid option set on removable media partitions (Not Scored)
  - 1.1.20 Ensure noexec option set on removable media partitions (Not Scored)
  - 1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)
  - 1.1.22 Disable Automounting (Scored)
  - 1.1.23 Disable USB Storage (Scored)
  - 1.2 Configure Software Updates
  - 1.2.1 Ensure package manager repositories are configured (Not Scored)
  - 1.2.2 Ensure GPG keys are configured (Not Scored)
  - 1.3 Configure sudo
  - 1.3.1 Ensure sudo is installed (Scored)
  - 1.3.2 Ensure sudo commands use pty (Scored)
  - 1.3.3 Ensure sudo log file exists (Scored)
  - 1.4 Filesystem Integrity Checking
  - 1.4.1 Ensure AIDE is installed (Scored)
  - 1.4.2 Ensure filesystem integrity is regularly checked (Scored)
  - 1.5 Secure Boot Settings
  - 1.5.1 Ensure permissions on bootloader config are configured (Scored)
  - 1.5.2 Ensure bootloader password is set (Scored)
  - 1.5.3 Ensure authentication required for single user mode (Scored)
  - 1.6 Additional Process Hardening
  - 1.6.1 Ensure XD/NX support is enabled (Scored)
  - 1.6.2 Ensure address space layout randomization (ASLR) is enabled (Scored)
  - 1.6.3 Ensure prelink is disabled (Scored)
  - 1.6.4 Ensure core dumps are restricted (Scored)
  - 1.7 Mandatory Access Control
  - 1.7.1 Configure AppArmor
  - 1.7.1.1 Ensure AppArmor is installed (Scored)
  - 1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration (Scored)
  - 1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Scored)
  - 1.7.1.4 Ensure all AppArmor Profiles are enforcing (Scored)
  - 1.8 Warning Banners
  - 1.8.1 Command Line Warning Banners
  - 1.8.1.1 Ensure message of the day is configured properly (Scored)
  - 1.8.1.2 Ensure local login warning banner is configured properly (Scored)
  - 1.8.1.3 Ensure remote login warning banner is configured properly (Scored).
  - 1.8.1.4 Ensure permissions on /etc/motd are configured (Scored)
  - 1.8.1.5 Ensure permissions on /etc/issue are configured (Scored)
  - 1.8.1.6 Ensure permissions on /etc/issue.net are configured (Scored)
  - 1.8.2 Ensure GDM login banner is configured (Scored)
  - 1.9 Ensure updates, patches, and additional security software are installed (Not Scored)

**2 Services**
  - 2.1 inetd Services
  - 2.1.1 Ensure xinetd is not installed (Scored)
  - 2.1.2 Ensure openbsd-inetd is not installed (Scored)
  - 2.2 Special Purpose Services
  - 2.2.1 Time Synchronization
  - 2.2.1.1 Ensure time synchronization is in use (Scored)
  - 2.2.1.2 Ensure systemd-timesyncd is configured (Not Scored)
  - 2.2.1.3 Ensure chrony is configured (Scored)
  - 2.2.1.4 Ensure ntp is configured (Scored)
  - 2.2.2 Ensure X Window System is not installed (Scored)
  - 2.2.3 Ensure Avahi Server is not enabled (Scored)
  - 2.2.4 Ensure CUPS is not enabled (Scored)
  - 2.2.5 Ensure DHCP Server is not enabled (Scored)
  - 2.2.6 Ensure LDAP server is not enabled (Scored)
  - 2.2.7 Ensure NFS and RPC are not enabled (Scored)
  - 2.2.8 Ensure DNS Server is not enabled (Scored)
  - 2.2.9 Ensure FTP Server is not enabled (Scored)
  - 2.2.10 Ensure HTTP server is not enabled (Scored)
  - 2.2.11 Ensure email services are not enabled (Scored)
  - 2.2.12 Ensure Samba is not enabled (Scored)
  - 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
  - 2.2.14 Ensure SNMP Server is not enabled (Scored)
  - 2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)
  - 2.2.16 Ensure rsync service is not enabled (Scored)
  - 2.2.17 Ensure NIS Server is not enabled (Scored)
  - 2.3 Service Clients
  - 2.3.1 Ensure NIS Client is not installed (Scored)
  - 2.3.2 Ensure rsh client is not installed (Scored)
  - 2.3.3 Ensure talk client is not installed (Scored)
  - 2.3.4 Ensure telnet client is not installed (Scored)
  - 2.3.5 Ensure LDAP client is not installed (Scored)

**3 Network Configuration**
  - 3.1 Disable unused network protocols and devices
  - 3.1.1 Disable IPv6 (Not Scored)
  - 3.1.2 Ensure wireless interfaces are disabled (Scored)
  - 3.2 Network Parameters (Host Only)
  - 3.2.1 Ensure packet redirect sending is disabled (Scored)
  - 3.2.2 Ensure IP forwarding is disabled (Scored)
  - 3.3 Network Parameters (Host and Router)
  - 3.3.1 Ensure source routed packets are not accepted (Scored)
  - 3.3.2 Ensure ICMP redirects are not accepted (Scored)
  - 3.3.3 Ensure secure ICMP redirects are not accepted (Scored)
  - 3.3.4 Ensure suspicious packets are logged (Scored)
  - 3.3.5 Ensure broadcast ICMP requests are ignored (Scored)
  - 3.3.6 Ensure bogus ICMP responses are ignored (Scored)
  - 3.3.7 Ensure Reverse Path Filtering is enabled (Scored)
  - 3.3.8 Ensure TCP SYN Cookies is enabled (Scored)
  - 3.3.9 Ensure IPv6 router advertisements are not accepted (Scored)
  - 3.4 Uncommon Network Protocols
  - 3.4.1 Ensure DCCP is disabled (Scored)
  - 3.4.2 Ensure SCTP is disabled (Scored)
  - 3.4.3 Ensure RDS is disabled (Scored)
  - 3.4.4 Ensure TIPC is disabled (Scored)
  - 3.5 Firewall Configuration
  - 3.5.1 Ensure Firewall software is installed
  - 3.5.1.1 Ensure a Firewall package is installed (Scored)
  - 3.5.2 Configure UncomplicatedFirewall
  - 3.5.2.1 Ensure ufw service is enabled (Scored)
  - 3.5.2.2 Ensure default deny firewall policy (Scored)
  - 3.5.2.3 Ensure loopback traffic is configured (Scored)
  - 3.5.2.4 Ensure outbound connections are configured (Not Scored)
  - 3.5.2.5 Ensure firewall rules exist for all open ports (Scored)
  - 3.5.3 Configure nftables
  - 3.5.3.1 Ensure iptables are flushed (Not Scored)
  - 3.5.3.2 Ensure a table exists (Scored)
  - 3.5.3.3 Ensure base chains exist (Scored)
  - 3.5.3.4 Ensure loopback traffic is configured (Scored)
  - 3.5.3.5 Ensure outbound and established connections are configured (Not Scored)
  - 3.5.3.6 Ensure default deny firewall policy (Scored)
  - 3.5.3.7 Ensure nftables service is enabled (Scored)
  - 3.5.3.8 Ensure nftables rules are permanent (Scored)
  - 3.5.4 Configure iptables
  - 3.5.4.1.1 Ensure default deny firewall policy (Scored)
  - 3.5.4.1.2 Ensure loopback traffic is configured (Scored)
  - 3.5.4.1.3 Ensure outbound and established connections are configured (Not Scored)
  - 3.5.4.1.4 Ensure firewall rules exist for all open ports (Scored)
  - 3.5.4.2.1 Ensure IPv6 default deny firewall policy (Scored)
  - 3.5.4.2.2 Ensure IPv6 loopback traffic is configured (Scored)
  - 3.5.4.2.3 Ensure IPv6 outbound and established connections are configured (Not Scored)
  - 3.5.4.2.4 Ensure IPv6 firewall rules exist for all open ports (Not Scored)

**4 Logging and Auditing**
  - 4.1 Configure System Accounting (auditd)
  - 4.1.1 Ensure auditing is enabled
  - 4.1.1.1 Ensure auditd is installed (Scored)
  - 4.1.1.2 Ensure auditd service is enabled (Scored)
  - 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored)
  - 4.1.1.4 Ensure audit_backlog_limit is sufficient (Scored)
  - 4.1.2 Configure Data Retention
  - 4.1.2.1 Ensure audit log storage size is configured (Scored)
  - 4.1.2.2 Ensure audit logs are not automatically deleted (Scored)
  - 4.1.2.3 Ensure system is disabled when audit logs are full (Scored)
  - 4.1.3 Ensure events that modify date and time information are collected (Scored)
  - 4.1.4 Ensure events that modify user/group information are collected (Scored)
  - 4.1.5 Ensure events that modify the system's network environment are collected (Scored)
  - 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
  - 4.1.7 Ensure login and logout events are collected (Scored)
  - 4.1.8 Ensure session initiation information is collected (Scored)
  - 4.1.9 Ensure discretionary access control permission modification events are collected (Scored)
  - 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
  - 4.1.11 Ensure use of privileged commands is collected (Scored)
  - 4.1.12 Ensure successful file system mounts are collected (Scored)
  - 4.1.13 Ensure file deletion events by users are collected (Scored)
  - 4.1.14 Ensure changes to system administration scope (sudoers) is collected (Scored)
  - 4.1.15 Ensure system administrator actions (sudolog) are collected (Scored)
  - 4.1.16 Ensure kernel module loading and unloading is collected (Scored)
  - 4.1.17 Ensure the audit configuration is immutable (Scored)
  - 4.2 Configure Logging
  - 4.2.1 Configure rsyslog
  - 4.2.1.1 Ensure rsyslog is installed (Scored)
  - 4.2.1.2 Ensure rsyslog Service is enabled (Scored)
  - 4.2.1.3 Ensure logging is configured (Not Scored)
  - 4.2.1.4 Ensure rsyslog default file permissions configured (Scored)
  - 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Scored)
  - 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)
  - 4.2.2 Configure journald
  - 4.2.2.1 Ensure journald is configured to send logs to rsyslog (Scored)
  - 4.2.2.2 Ensure journald is configured to compress large log files (Scored)
  - 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Scored)
  - 4.2.3 Ensure permissions on all logfiles are configured (Scored)
  - 4.3 Ensure logrotate is configured (Not Scored)
  - 4.4 Ensure logrotate assigns appropriate permissions (Scored)

**5 Access, Authentication and Authorization**
  - 5.1 Configure cron
  - 5.1.1 Ensure cron daemon is enabled (Scored)
  - 5.1.2 Ensure permissions on /etc/crontab are configured (Scored)
  - 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)
  - 5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)
  - 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)
  - 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)
  - 5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)
  - 5.1.8 Ensure at/cron is restricted to authorized users (Scored)
  - 5.2 SSH Server Configuration
  - 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
  - 5.2.2 Ensure permissions on SSH private host key files are configured (Scored)
  - 5.2.3 Ensure permissions on SSH public host key files are configured (Scored)
  - 5.2.4 Ensure SSH Protocol is not set to 1 (Scored)
  - 5.2.5 Ensure SSH LogLevel is appropriate (Scored)
  - 5.2.6 Ensure SSH X11 forwarding is disabled (Scored)
  - 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
  - 5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)
  - 5.2.9 Ensure SSH HostbasedAuthentication is disabled (Scored)
  - 5.2.10 Ensure SSH root login is disabled (Scored)
  - 5.2.11 Ensure SSH PermitEmptyPasswords is disabled (Scored)
  - 5.2.12 Ensure SSH PermitUserEnvironment is disabled (Scored)
  - 5.2.13 Ensure only strong Ciphers are used (Scored)
  - 5.2.14 Ensure only strong MAC algorithms are used (Scored)
  - 5.2.15 Ensure only strong Key Exchange algorithms are used (Scored)
  - 5.2.16 Ensure SSH Idle Timeout Interval is configured (Scored)
  - 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less (Scored)
  - 5.2.18 Ensure SSH access is limited (Scored)
  - 5.2.19 Ensure SSH warning banner is configured (Scored)
  - 5.2.20 Ensure SSH PAM is enabled (Scored)
  - 5.2.21 Ensure SSH AllowTcpForwarding is disabled (Scored)
  - 5.2.22 Ensure SSH MaxStartups is configured (Scored)
  - 5.2.23 Ensure SSH MaxSessions is limited (Scored)
  - 5.3 Configure PAM
  - 5.3.1 Ensure password creation requirements are configured (Scored)
  - 5.3.2 Ensure lockout for failed password attempts is configured (Scored)
  - 5.3.3 Ensure password reuse is limited (Scored)
  - 5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)
  - 5.4 User Accounts and Environment
  - 5.4.1 Set Shadow Password Suite Parameters
  - 5.4.1.1 Ensure password expiration is days or less (Scored)
  - 5.4.1.2 Ensure minimum days between password changes is configured (Scored)
  - 5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)
  - 5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)
  - 5.4.1.5 Ensure all users last password change date is in the past (Scored)
  - 5.4.2 Ensure system accounts are secured (Scored)
  - 5.4.3 Ensure default group for the root account is GID 0 (Scored)
  - 5.4.4 Ensure default user umask is or more restrictive (Scored)
  - 5.4.5 Ensure default user shell timeout is seconds or less (Scored)
  - 5.5 Ensure root login is restricted to system console (Not Scored)
  - 5.6 Ensure access to the su command is restricted (Scored)

**6 System Maintenance**
  - 6.1 System File Permissions
  - 6.1.1 Audit system file permissions (Not Scored)
  - 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
  - 6.1.3 Ensure permissions on /etc/gshadow- are configured (Scored)
  - 6.1.4 Ensure permissions on /etc/shadow are configured (Scored)
  - 6.1.5 Ensure permissions on /etc/group are configured (Scored)
  - 6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)
  - 6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)
  - 6.1.8 Ensure permissions on /etc/group- are configured (Scored)
  - 6.1.9 Ensure permissions on /etc/gshadow are configured (Scored)
  - 6.1.10 Ensure no world writable files exist (Scored)
  - 6.1.11 Ensure no unowned files or directories exist (Scored)
  - 6.1.12 Ensure no ungrouped files or directories exist (Scored)
  - 6.1.13 Audit SUID executables (Not Scored)
  - 6.1.14 Audit SGID executables (Not Scored)
  - 6.2 User and Group Settings
  - 6.2.1 Ensure password fields are not empty (Scored)
  - 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)
  - 6.2.3 Ensure all users' home directories exist (Scored).
  - 6.2.4 Ensure no legacy "+" entries exist in /etc/shadow (Scored)
  - 6.2.5 Ensure no legacy "+" entries exist in /etc/group (Scored)
  - 6.2.6 Ensure root is the only UID 0 account (Scored)
  - 6.2.7 Ensure root PATH Integrity (Scored)
  - 6.2.8 Ensure users' home directories permissions are or more restrictive (Scored)
  - 6.2.9 Ensure users own their home directories (Scored)
  - 6.2.10 Ensure users' dot files are not group or world writable (Scored)
  - 6.2.11 Ensure no users haveforward files (Scored)
  - 6.2.12 Ensure no users havenetrc files (Scored)
  - 6.2.13 Ensure users'netrc Files are not group or world accessible (Scored)
  - 6.2.14 Ensure no users haverhosts files (Scored)
  - 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)
  - 6.2.16 Ensure no duplicate UIDs exist (Scored)
  - 6.2.17 Ensure no duplicate GIDs exist (Scored)
  - 6.2.18 Ensure no duplicate user names exist (Scored)
  - 6.2.19 Ensure no duplicate group names exist (Scored)
  - 6.2.20 Ensure shadow group is empty (Scored)


_________________


License
-------

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

Author Information
------------------

[Denis Bernacci](https://www.linkedin.com/in/denis-bernacci-486339206/)

This repository is a migration from Ubuntu 20.04 (https://github.com/alivx/CIS-Ubuntu-20.04-Ansible/).

Pull requests and GitHub issues are welcome!
