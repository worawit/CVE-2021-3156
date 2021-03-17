# CVE-2021-3156 (Sudo Baron Samedit)

This repository is CVE-2021-3156 exploit targeting Linux x64. For writeup, please visit https://datafarm-cybersecurity.medium.com/exploit-writeup-for-cve-2021-3156-sudo-baron-samedit-7a9a4282cb31  
Credit to [Braon Samedit of Qualys for the original advisory](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt).

---

### Files

##### Exploit on glibc with tcache
 * **exploit_nss.py** auto detect all requirements and number of entries in /etc/nsswitch.conf
 * **exploit_nss_manual.py** simplified version of exploit_nss.py for better exploit understanding
 * **exploit_timestamp_race.c** overwrite def_timestamp and race condition to modify /etc/passwd

##### Exploit on glibc without tcache
 * **exploit_defaults_mailer.py** the exploit overwrite struct defaults to modify mailer binary path. It requires sudo compiled without disable-root-mailer such as CentOS 6 and 7.
 * **exploit_userspec.py** the exploit overwrite struct userspec to bypass authentication and add a new user in /etc/passwd. Support only sudo version 1.8.9-1.8.23.
 * **exploit_cent7_userspec.py** simplified version of exploit_userspec.py for understanding but target only CentOS 7 with default configuration
 * **exploit_nss_d9.py** overwrite struct service_user on Debian 9 but support only default /etc/nsswith.conf
 * **exploit_nss_u16.py** overwrite struct service_user on Ubuntu 16.04 but support only default /etc/nsswith.conf
 * **exploit_nss_u14.py** overwrite struct service_user on Ubuntu 14.04 but support only default /etc/nsswith.conf

##### Others
 * **asm/** tinyelf library and executable for embedded in python exploit
 * **gdb/** scripts that used for debugging sudo heap

---

### Choosing exploit
*For Linux distributions that glibc has tcache support and enabled (CentOS 8, Ubuntu >= 17.10, Debian 10):*
 * try **exploit_nss.py** first
 * If an error is not glibc tcache related, you can try **exploit_timestamp_race.c** next

*For Linux distribution that glibc has no tcache support:*
 * if a target is Debian 9, Ubuntu 16.04, or Ubuntu 14.04, try **exploit_nss_xxx.py** for specific version first
 * next, try **exploit_defaults_mailer.py**. If you know a target sudo is compiled with *--disable-root-mailer*, you can skip this exploit. The exploit attempt to check root mailer flag from sudo binary. But sudo permission on some Linux distribution is 4711 (-rws--x--x) which is impossible to check on target system. (Known work OS is CentOS 6 and 7)
 * last, try **exploit_userspec.py**
