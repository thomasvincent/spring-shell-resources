### Last Updated May 2024


# Spring4Shell (SpringShell) Resource List

A curated list of resources for understanding and addressing the Spring4Shell (SpringShell) remote code execution vulnerability in Spring Framework (CVE-2022-22965).

## Official Spring Resources

* [Spring Framework RCE Vulnerability Official Announcement](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)
* [CVE-2022-22965 Vulnerability Details](https://tanzu.vmware.com/security/cve-2022-22965)
* [Spring Cloud Function CVE Publication](https://spring.io/blog/2022/03/29/cve-report-published-for-spring-cloud-function)
* [Spring Blog - Spring Framework RCE Vulnerability FAQ](https://spring.io/blog/2022/04/01/spring-framework-rce-vulnerability-faq)

## Vulnerability Databases

* [National Vulnerability Database (NVD) - CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) - Official U.S. government repository of vulnerability data
* [Mitre CVE - CVE-2022-22965](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965) - Collaborative effort to identify and catalog vulnerabilities
* [Atomist Image Vulnerability Database](https://dso.atomist.com/cve/CVE-2022-22965) - Detailed technical information and affected versions
* [Tenable Plugins for CVE-2022-22965](https://www.tenable.com/plugins/nessus/161337) - Vulnerability detection plugin for Tenable Nessus scanner

## Vendor Responses and Guidance

* [VMware Advisory for CVE-2022-22965](https://www.vmware.com/security/advisories/VMSA-2022-0010.html) - Addresses impact on VMware Tanzu and Spring Cloud Gateway
* [Cloudflare WAF Mitigations for Spring4Shell](https://blog.cloudflare.com/waf-mitigations-sping4shell/) - Guidance for using Cloudflare Web Application Firewall to protect applications
* [Akamai Spring4Shell Mitigation Guide](https://www.akamai.com/blog/security-research/spring4shell-mitigation-with-akamai) - Recommendations for using Akamai platform to mitigate risks
* [Amazon Web Services - Spring4Shell Vulnerability Guidance](https://aws.amazon.com/security/security-bulletins/AWS-2022-007/) - AWS security bulletin and mitigation recommendations
* [Oracle Security Alert for CVE-2022-22965](https://www.oracle.com/security-alerts/alert-cve-2022-22965.html) - Advisory for Oracle products affected by Spring4Shell
* [Microsoft Spring4Shell Vulnerability Guidance](https://msrc-blog.microsoft.com/2022/03/31/guidance-for-preventing-detecting-and-hunting-for-cve-2022-22965-spring4shell-exploits/) - Mitigation and detection guidance from Microsoft
* [IBM Spring4Shell Vulnerability Bulletin](https://www.ibm.com/support/pages/node/6564444) - Details on affected IBM products and remediation steps
* [Red Hat Spring Boot RCE Vulnerability Response](https://access.redhat.com/security/vulnerabilities/RHSB-2022-002) - Red Hat's response to the Spring4Shell vulnerability

## Mitigation and Detection

* [CISA Alert on Spring4Shell](https://www.cisa.gov/uscert/ncas/current-activity/2022/03/31/spring-framework-remote-code-execution-vulnerability-affecting) - Official guidance from U.S. Cybersecurity and Infrastructure Security Agency
* [Rapid7 Spring4Shell Mitigation Guide](https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/) - Comprehensive overview of vulnerability and mitigation steps
* [Palo Alto Networks Spring4Shell Protection](https://www.paloaltonetworks.com/blog/prisma-cloud/spring4shell-vulnerability-protection/) - Guidance for detecting and preventing exploitation attempts
* [Trend Micro - Analyzing Spring4Shell Exploits and Mitigations](https://www.trendmicro.com/en_us/research/22/d/cve-2022-22965-analyzing-the-exploitation-of-spring4shell-vulner.html) - Detailed analysis of exploit attempts and defense strategies

## Testing and Validation

* [Cyber Kendra Spring4Shell Scanner](https://github.com/CyberKendra/Spring4Shell-POC) - Proof-of-concept scanner for identifying vulnerable applications
* [Splunk Spring4Shell Detection Queries](https://www.splunk.com/en_us/blog/security/detecting-spring4shell-cve-2022-22965-with-splunk.html) - Search queries to detect potential exploitation attempts in Splunk
* [FullHunt Spring4Shell Vulnerability Scanner](https://github.com/fullhunt/spring4shell-scan) - Open-source scanner to detect vulnerable Spring Framework instances
* [Nmap NSE Script for Spring4Shell Detection](https://github.com/Diverto/nse-spring4shell) - Nmap script to scan for vulnerable servers
* [Spring4Shell Vulnerability Detection with Nuclei](https://blog.projectdiscovery.io/spring4shell-springing-into-action/) - Tutorial on using Nuclei to detect Spring4Shell vulnerability

## Community Discussions and Analysis

* [Spring Community Forum - Spring4Shell Discussion](https://forum.spring.io/forum/spring-projects/security/179222-cve-2022-22965-spring4shell) - Active community thread discussing the vulnerability and mitigation strategies
* [/r/springboot - Spring4Shell Megathread](https://www.reddit.com/r/springboot/comments/tsy0c6/spring4shell_megathread_cve202222965/) - Reddit discussion with updates and resources
* [Stack Overflow - Spring4Shell Tag](https://stackoverflow.com/questions/tagged/spring4shell) - Collection of questions and answers related to the vulnerability
* [Praetorian - Deep Dive into Spring4Shell](https://www.praetorian.com/blog/spring-framework-remote-code-execution-spring4shell-explained/) - Detailed technical analysis of the vulnerability and exploitation techniques
* [LunaSec - Spring4Shell: Detecting and Defending](https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/) - Practical guide for detecting and protecting against Spring4Shell
* [/r/java](https://www.reddit.com/r/java/) - Reddit community for Java programming language
* [/r/netsec](https://www.reddit.com/r/netsec/) - Reddit community for network security discussions
* [Information Security Stack Exchange](https://security.stackexchange.com/questions/tagged/spring4shell) - Q&A site for information security professionals
* [Stack Overflow - Spring Framework](https://stackoverflow.com/questions/tagged/spring) - Q&A site for programming questions related to Spring Framework
* [#Spring4Shell on Twitter](https://twitter.com/hashtag/Spring4Shell) - Tweets related to Spring4Shell vulnerability
* [#SpringShell on Twitter](https://twitter.com/hashtag/SpringShell) - Tweets related to SpringShell vulnerability
* [@SpringCentral on Twitter](https://twitter.com/SpringCentral) - Official Twitter account for Spring Framework

## Patch and Upgrade Information

* [Spring Framework 5.3.18 Release Notes](https://github.com/spring-projects/spring-framework/releases/tag/v5.3.18) - Official release notes for the patched 5.3.x version
* [Spring Framework 5.2.20 Release Notes](https://github.com/spring-projects/spring-framework/releases/tag/v5.2.20) - Official release notes for the patched 5.2.x version
* [Spring Boot 2.6.6 Release Notes](https://github.com/spring-projects/spring-boot/releases/tag/v2.6.6) - Release notes for Spring Boot 2.6.6, which includes patched Spring Framework versions

## Tools and Scripts

* [Detectify Crowdsource - Spring4Shell Test Request](https://cs.detectify.com/post/7c40a4c3-c75a-4917-9acc-8e4e3093d6da) - Crowdsourced test case for detecting Spring4Shell vulnerability
* [Burp Suite Extension - Active Scan ++](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976) - Burp Suite extension that includes a check for Spring4Shell
* [Spring4Shell Exploit POC](https://github.com/BobTheShoplifter/Spring4Shell-POC) - Proof-of-concept exploit code for the Spring4Shell vulnerability
* [Spring4Shell Lab Environment](https://github.com/adioss/spring4shell-lab) - Dockerized environment for practicing Spring4Shell exploitation and detection
* [Spring4Shell Vulnerability Scanner by Netsparker](https://www.netsparker.com/blog/web-security/spring4shell-rce-cve-2022-22965/) - Web-based scanner to identify vulnerable Spring applications
* [Spring4Shell Exploitation with Metasploit](https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/) - Guide on exploiting Spring4Shell using Metasploit Framework

## CERT

* [VU#970766 Spring Framework insecurely handles PropertyDescriptor objects with data binding](https://www.kb.cert.org/vuls/id/970766) - Carnegie Mellon University's CERT Coordination Center's Vulnerability Note

## MITRE CVE

* CVE-2022-22947
  * [CVE-2022-22947](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22947)
  * [Official VMware Post](https://tanzu.vmware.com/security/cve-2022-22947)
* CVE-2022-22950
  * [CVE-2022-22950](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22950)
  * [Official VMware Post](https://tanzu.vmware.com/security/cve-2022-22947)
* CVE-2022-22963
  * [CVE-2022-22963](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-CVE-2022-22963)
  * [Official Spring Project Post](https://spring.io/blog/2022/03/29/cve-report-published-for-spring-cloud-function)
* CVE-2022-22965
  * [CVE-2022-22965](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965)
  * [Official Spring Project Post](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)
