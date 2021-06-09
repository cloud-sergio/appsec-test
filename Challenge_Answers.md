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


Challenge 2: Maven Dependency Resolution Test

The test results is reporting the following:

Testing /mnt/c/Users/siwilkins/Scripting/Projects/appsec_test/challenge_2:maven-dependency-test...
Tested 31 dependencies for known issues, found 98 issues, 98 vulnerable paths.

Issues to fix by upgrading:
Upgrade com.fasterxml.jackson.core:jackson-databind@2.7.9.4 to com.fasterxml.jackson.core:jackson-databind@2.9.10.8 to fix

&

Upgrade org.springframework.boot:spring-boot-starter-web@1.1.1.RELEASE to org.springframework.boot:spring-boot-starter-web@2.3.0.RELEASE to fix
However 2.3.0 still leaves High Severity Vulnerabilities to fix these remaining vulnerabilities there is information close to the end of the test result file, which states that version
spring-web@4.0.5.RELEASE will fix these issues.




Challenge 3: Vulnerable Java Test

Example 1:
// Mitigating SQL Injection vulnerability:

String sql_query = "SELECT * FROM users WHERE userid =? AND password=?";
PreparedStatement prepStmt = conn.prepareStatement(sql_query);
prepStmt.setString(1, username); 
prepStmt.setString(2, Base64.getEncoder().encodeToString(passwordString.getBytes()));
prepStmt.executeUpdate();
prepStmt.close();


Example 2:
// Added Try Catch to minimize risk of errors from user input
	try{
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String s = br.readLine(); //VIOLATION, 
		mb.post(s)
	}
	catch(Exception e){}
  
  
  Example 3:
  // URL Validation
String url = request.getParameter("hidden_url"); // not so hidden...
URL url = new URL(url); // VIOLATION 
InputStream is = url.openConnection().getContent();
//Build an url validator 
//Class UrlValidator Default schemes: {https,http,ftp} 
UrlValidator urlValidator = new UrlValidator();
//perform zero trust
if (urlValidator.isValid(url) {
      URL url = new URL(url); 
      InputStream is = url.openConnection().getContent();
//	System.out.println("URL is valid");
    } else {
      	System.out.println("URL is not valid");
    }




Challenge 4: Automated Certificate Expiration Checker

1. Identify which public subnets belong to Overstock.com, 
              Public Subnet Range: 173.241.144.0 - 173.241.159.255
nslookup

> server 8.8.8.8
Default Server:  dns.google
Address:  8.8.8.8

> overstock.com
Server:  dns.google
Address:  8.8.8.8

Non-authoritative answer:
Name:    overstock.com
Address:  173.241.154.15

Using this IP I was able to gain more information with whois:
IP Location	United States United States Salt Lake City Overstock.com
ASN	United States AS25655 OSTK-COM, US (registered Apr 15, 2002)
Resolve Host	overstock.ca
Whois Server	whois.arin.net
IP Address	173.241.154.15
Reverse IP	5 websites use this address.
NetRange:       173.241.144.0 - 173.241.159.255
CIDR:           173.241.144.0/20
NetName:        OVERSTOCK
NetHandle:      NET-173-241-144-0-1
Parent:         NET173 (NET-173-0-0-0-0)
NetType:        Direct Assignment
OriginAS:       AS25655
Organization:   Overstock.com (OVERST)
RegDate:        2010-04-26
Updated:        2012-03-02
Ref:            https://rdap.arin.net/registry/ip/173.241.144.0

OrgName:        Overstock.com
OrgId:          OVERST
Address:        6350 South 3000 East
City:           Salt Lake City
StateProv:      UT
PostalCode:     84121-6931
Country:        US
RegDate:        2000-01-04
Updated:        2014-10-28
Ref:            https://rdap.arin.net/registry/entity/OVERST


I was not able to find more information from research it seems there is no simple way to find all public IP ranges for a company. I found the IP range using whois, but this does not mean that this is all public subnets.



2. Build a tool that can scan those subnets to identify hosts listening on port 443 using docker
    One could use NMap to determine which hosts are listening on Port 443.
    The syntax for this command would be:
      nmap -sT -p 443 overstock.com
    

3. Once those servers are identified, extract the HTTPS certificate and parse the validity information to see when it will expire.
    Check the expiration date of an SSL certificate:
      Open a UNIX command line window.
      Perform a query such as, openssl s_client -servername <NAME> -connect <HOST:PORT> 2>/dev/null | openssl x509 -noout -dates . The expiration date appears in the response as notAfter=<expiration_date>

4. Generate output that can be used to determine which certificates are (1) already expired or (2) will expire within the next year. This can be an email or a report, but it should be understandable and efficiently denote which certificates should be prioritized for update.
      After running the UNIX command from question 3, we can generate a report or email by listing the information and organizing certificates based on expiry date from soonest to latest.
      


Docker Project:

The following docker project seems to have outlined the requirements for this challenge. This project has been updated recently and does the following:
Certificate Expiry Monitor Controller monitors the expiration of TLS certificates used in Ingress. 

docker pull mercari/certificate-expiry-monitor-controller
