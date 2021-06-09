# appsec-test
Challenge 1: Python Docker Test

CVE-2018-18074

The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.

Reference of CVE: https://nvd.nist.gov/vuln/detail/CVE-2018-18074s

Resolution of vulnerability:
1. Within requirements.txt requests is specifies version 2.19.0
2. To resolve this vulnerability we need to update the version of requests to version 2.20.0 or newer.
3. We can remediate this vulnerability by changing requests.txt to at least version 2.20.0, since the latest version of requests is 2.25.1 I have posted my resolution using that version.

beautifulsoup4==4.7.1
fastapi==0.10.2
requests==2.25.1
email-validator==1.0.3


CVE-2018-100517

No vulnerabilities were found when searching for cve-2018-100517. I checked multiple different site for this CVE, but was unable to find any vulnerabilities.


CVE-2018-12699

finish_stab in stabs.c in GNU Binutils 2.30 allows attackers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact, as demonstrated by an out-of-bounds write of 8 bytes. This can occur during execution of objdump.


Reference of CVE: https://nvd.nist.gov/vuln/detail/CVE-2018-12699

Resolution of vulnerability:
1. I don't see in the Dockerfile or in any of the files where binutils is being used.
2. Based on the fact that GNU Binutils 2.30 is the version that is mentioned by NIST. Remediation would likely be to update binutils, since I don't see it in our code, to remediate I believe the correct solution is to update the version of alpine that we are currently using.
3. The latest release of alpine is 3.13.5.
