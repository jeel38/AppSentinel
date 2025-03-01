# AppSentinel: Vigilant Guard for Mobile Applications and URL Vulnerabilities🛡️🔍
Mobile Security Scanner is a static analysis tool designed to detect security vulnerabilities in Android (APK), iOS (IPA) applications, and URLs. This tool helps developers and security professionals identify misconfigurations, hard-coded secrets, and common security risks that could expose sensitive data.

## Android Security Analysis 🤖 
The tool performs static analysis on APK files by extracting and analyzing the AndroidManifest.xml to detect exposed components, permission misconfigurations, and security weaknesses. It scans for hard-coded secrets such as API keys, OAuth credentials, Firebase links, AWS S3 bucket configurations, and IP addresses. Additionally, it retrieves package names, main activity names, emails, and embedded strings to identify potential security risks.

## iOS Security Analysis 🍏 
For iOS IPA analysis, the tool inspects the Info.plist file to identify security misconfigurations, including insecure ATS settings, exposed URL schemes, and hard-coded credentials. It also extracts metadata to detect leaked API keys, Firebase links, and sensitive configurations that could be exploited by attackers.

## URL Vulnerability Scanning 🔗 
The tool evaluates URLs for common web vulnerabilities, including Subdomain Takeover, SQL Injection, Cross-Site Scripting (XSS), Open Redirect, and Local File Inclusion (LFI) threats. By scanning for these security risks, it helps prevent unauthorized access, data leaks, and exploitation of web applications.

## Requirement 🛠️

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

### Cross-Platform Setup Instructions

1. For Kali Linux
```
# Install system dependencies
sudo apt update && sudo apt install -y \
    python3-pip \
    apktool \
    openjdk-11-jdk \
    android-sdk \
    golang

# Set Android SDK path
echo 'export ANDROID_HOME=/usr/lib/android-sdk' >> ~/.bashrc
source ~/.bashrc

# Install Go tools
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest

# Clone security tools
git clone https://github.com/Parameter-SecURITY/SQLiDetector.git
git clone https://github.com/jiyoches/webster

# Install Python requirements
pip3 install -r requirements.txt
```
2. For macOS
```
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install \
    python@3.10 \
    apktool \
    openjdk \
    android-sdk \
    golang

# Set Android SDK path
echo 'export ANDROID_HOME=$HOME/Library/Android/sdk' >> ~/.zshrc
source ~/.zshrc

# Rest same as Kali Linux instructions from Go tools onward
```
### Automated Setup Scripts
Linux/macOS Setup Script (setup.sh)
```
#!/bin/bash

# Check OS and install dependencies
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt update && sudo apt install -y python3-pip apktool openjdk-11-jdk android-sdk golang
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew install python@3.10 apktool openjdk android-sdk golang
fi

# Setup environment
export ANDROID_HOME=$([ "$OSTYPE" == "darwin"* ] && echo "$HOME/Library/Android/sdk" || echo "/usr/lib/android-sdk")
echo "export ANDROID_HOME=$ANDROID_HOME" >> $HOME/.${SHELL##*/}rc

# Install Go tools
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest

# Clone tools
git clone https://github.com/Parameter-SecURITY/SQLiDetector.git
git clone https://github.com/jiyoches/webster

# Python setup
pip3 install -r requirements.txt

echo "Setup complete! Restart your shell."
```

## How to run 🚀

Step 1: Clone the Repository
```
git clone https://github.com/jeel38/AppSentinel.git
```
Step 2: Install requirement tools
```
./setup.sh
```
Step 3: Start the Flask Application
```
python3 app.py
```
Step 4: Access the Application

Open your web browser and navigate to ``` http://localhost:5000 ```
