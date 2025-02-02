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

## Implementation
APK Static Analysis
<img width="1027" alt="Screenshot 2025-02-03 at 12 16 40 AM" src="https://github.com/user-attachments/assets/7351e5ac-a9a1-45df-97be-512049f6ac01" />
<img width="1029" alt="Screenshot 2025-02-03 at 12 17 20 AM" src="https://github.com/user-attachments/assets/5a3c1db1-cf71-4125-8665-8a555ecaa78e" />
<img width="1013" alt="Screenshot 2025-02-03 at 12 17 40 AM" src="https://github.com/user-attachments/assets/5de5e1ef-9237-439a-86b4-67c161388b96" />
APK ManiFest File Analysis - Vulnerability Result
<img width="1019" alt="Screenshot 2025-02-03 at 12 17 51 AM" src="https://github.com/user-attachments/assets/516029a9-ee84-49c9-91af-68a38d4b65a6" />
IPA Info.Plist File Analysis - Vulnerability Result
<img width="1023" alt="Screenshot 2025-02-03 at 12 18 11 AM" src="https://github.com/user-attachments/assets/dee06795-6ab3-43ed-bb75-0201bdecc9e7" />
Static Analysis - Firebase miss-configuration
<img width="1179" alt="Screenshot 2025-02-03 at 12 18 33 AM" src="https://github.com/user-attachments/assets/70caaf0b-60ba-4bf5-a590-e0bded52c700" />
Static Analysis - Cloud miss-configuration
<img width="1174" alt="Screenshot 2025-02-03 at 12 18 42 AM" src="https://github.com/user-attachments/assets/077d2d1b-cb2e-4d29-8f96-688203aeb341" />
Static Analysis - Vulnerable Google API Keys
<img width="1190" alt="Screenshot 2025-02-03 at 12 18 55 AM" src="https://github.com/user-attachments/assets/11cead51-e8cc-4705-9711-27e617875064" />
URLs Vulnerability Check
<img width="1029" alt="Screenshot 2025-02-03 at 12 19 30 AM" src="https://github.com/user-attachments/assets/133dd8a5-85c0-4a2b-9b66-f3596bcdaebf" />
URLs Vulnerability - SubDomain TakeOver Result
<img width="1018" alt="Screenshot 2025-02-03 at 12 19 50 AM" src="https://github.com/user-attachments/assets/2e09233e-2098-44f9-9b99-8ca7b47046c1" />
URLs Vulnerability - Open Redirect Vulnerability Result
<img width="1017" alt="Screenshot 2025-02-03 at 12 20 20 AM" src="https://github.com/user-attachments/assets/b261d9ec-93c0-4c42-918f-aa5d935e1f4e" />
URLs Vulnerability - LFI Vulnerability Result
<img width="1074" alt="Screenshot 2025-02-03 at 12 20 29 AM" src="https://github.com/user-attachments/assets/7e310021-2247-44a3-abf9-55a04a2faeaa" />
URLs Vulnerability - SQL Injection Vulnerability Result
<img width="992" alt="Screenshot 2025-02-03 at 12 20 40 AM" src="https://github.com/user-attachments/assets/86c53498-0285-4166-a802-764d7279004b" />


