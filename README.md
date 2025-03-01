# AppSentinel: Vigilant Guard for Mobile Applications and URL Vulnerabilities🛡️🔍
Mobile Security Scanner is a static analysis tool designed to detect security vulnerabilities in Android (APK), iOS (IPA) applications, and URLs. This tool helps developers and security professionals identify misconfigurations, hard-coded secrets, and common security risks that could expose sensitive data.

## Android Security Analysis 🤖 
The tool performs static analysis on APK files by extracting and analyzing the AndroidManifest.xml to detect exposed components, permission misconfigurations, and security weaknesses. It scans for hard-coded secrets such as API keys, OAuth credentials, Firebase links, AWS S3 bucket configurations, and IP addresses. Additionally, it retrieves package names, main activity names, emails, and embedded strings to identify potential security risks.

## iOS Security Analysis 🍏 
For iOS IPA analysis, the tool inspects the Info.plist file to identify security misconfigurations, including insecure ATS settings, exposed URL schemes, and hard-coded credentials. It also extracts metadata to detect leaked API keys, Firebase links, and sensitive configurations that could be exploited by attackers.

## URL Vulnerability Scanning 🔗 
The tool evaluates URLs for common web vulnerabilities, including Subdomain Takeover, SQL Injection, Cross-Site Scripting (XSS), Open Redirect, and Local File Inclusion (LFI) threats. By scanning for these security risks, it helps prevent unauthorized access, data leaks, and exploitation of web applications.

## Requirdemnt 🛠️

### Core Requirements

1. Python 3.7+ with pip
2. Android SDK Build-Tools (for aapt)
3. Apktool (APK reverse engineering)
4. Apkleaks (Secrets scanning)
5. Sublist3r (Subdomain enumeration)
6. Nuclei (Vulnerability scanning)
7. Waybackurls (URL discovery)
8. GF (Pattern matching)
9. Uro (URL filtering)
10. SQLiDetector
11. Webster (Open Redirect POC)

### Python Packages (requirements.txt)
```
flask==2.0.1
requests==2.26.0
plistlib==1.0
lxml==4.6.3
sublist3r==1.0
apkleaks==2.1.0
uro==1.0.1
```
