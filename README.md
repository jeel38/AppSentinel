# AppSentinel: Vigilant Guard for Mobile Applications and URL Vulnerabilities
Mobile Security Scanner is a static analysis tool designed to detect security vulnerabilities in Android (APK), iOS (IPA) applications, and URLs. This tool helps developers and security professionals identify misconfigurations, hard-coded secrets, and common security risks that could expose sensitive data.

## Android Security Analysis
The tool performs static analysis on APK files by extracting and analyzing the AndroidManifest.xml to detect exposed components, permission misconfigurations, and security weaknesses. It scans for hard-coded secrets such as API keys, OAuth credentials, Firebase links, AWS S3 bucket configurations, and IP addresses. Additionally, it retrieves package names, main activity names, emails, and embedded strings to identify potential security risks.

## iOS Security Analysis 
For iOS IPA analysis, the tool inspects the Info.plist file to identify security misconfigurations, including insecure ATS settings, exposed URL schemes, and hard-coded credentials. It also extracts metadata to detect leaked API keys, Firebase links, and sensitive configurations that could be exploited by attackers.

## URL Vulnerability Scanning
The tool evaluates URLs for common web vulnerabilities, including Subdomain Takeover, SQL Injection, Cross-Site Scripting (XSS), Open Redirect, and Local File Inclusion (LFI) threats. By scanning for these security risks, it helps prevent unauthorized access, data leaks, and exploitation of web applications.
