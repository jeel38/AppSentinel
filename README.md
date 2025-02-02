# AppSentinel: Mobile & URL Security Analysis
AppSentinel enhances mobile and web security by performing static analysis on Android (APK) and iOS (IPA) files, identifying vulnerabilities such as hard-coded secrets, API keys, Firebase links, and misconfigurations. It also evaluates URLs for threats like Subdomain Takeover, SQL Injection, XSS, Open Redirect, and LFI. By providing detailed insights, AppSentinel helps developers and security professionals strengthen application security and mitigate potential risks effectively.

## Static Analysis of Android APKs
Static analysis is a critical component of identifying vulnerabilities in mobile applications. This
methodology involves examining the APK (Android Package Kit) files of Android applications to
uncover potential security risks. The primary steps include analyzing the Android Manifest file,
computing hash values, identifying package and main activity names, and detecting hard-coded
secrets, Firebase links, IP addresses, Google API keys, Google OAuth values, and AWS S3
configurations.
## Static Analysis of iOS IPAs
Static analysis of iOS applications involves examining IPA (iOS App Store Package) files to uncover
potential security vulnerabilities. This process is crucial for identifying issues before they can be
exploited in a production environment. The primary focus of this analysis is the Info.plist file, which
contains key configuration details of the application. This chapter provides a detailed explanation of the
steps involved in the static analysis of iOS IPAs.
## URL Vulnerability Checker
In addition to analyzing mobile application files, the tool also evaluates URLs for potential
vulnerabilities. This includes checking for common web-based threats such as subdomain takeover, SQL
injection, cross-site scripting (XSS), open redirects, and local file inclusion (LFI). This chapter provides
a detailed explanation of each URL vulnerability type and the methods used to detect them.

## Project Installation
1. Python Version: Python 3.x\
2. Dependencies: Ensure the following tools and packages are installed:
 - Flask
 - aapt (Android SDK)
 - apktool
 - zipfile
 - plistlib
 - subprocess
 - re
 - werkzeug
 - hashlib
 - json
 - urllib
3. Install the necessary Python packages using pip:

```sh
pip install flask werkzeug
```
## How to Run

Step 1: Clone the Repository (if applicable):

```
git clone <repository-url>
cd <repository-directory>
```
Step 2: Start the Flask Application:
```
python3 app.py
```
Step 3: Access the Application:
Open your web browser and navigate to http://localhost:5000 
