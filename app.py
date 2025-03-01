from flask import Flask, request, render_template, send_file, render_template_string, url_for
import hashlib
import os
from werkzeug.utils import secure_filename
import zipfile
import plistlib
import subprocess
import re
import html
import shutil
import subprocess
import requests
import zipfile
import tempfile
from shutil import rmtree
import json 
from urllib.parse import urlparse

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def extract_apk_info(file_path):
    try:
        aapt_output = subprocess.check_output(['aapt', 'dump', 'badging', file_path]).decode('utf-8')
        package_name_match = re.search(r"package: name='([\w\.]+)'", aapt_output)
        main_activity_match = re.search(r"launchable-activity: name='([\w\.]+)'", aapt_output)
        package_name = package_name_match.group(1) if package_name_match else None
        main_activity_name = main_activity_match.group(1) if main_activity_match else None
        return package_name, main_activity_name
    except FileNotFoundError:
        print("Error: 'aapt' tool not found. Please make sure Android SDK is installed and 'aapt' is accessible.")
        return None, None
    except subprocess.CalledProcessError:
        print("Error: Failed to extract package info using 'aapt'.")
        return None, None

def extract_ipa_package_name(file_path):
    with zipfile.ZipFile(file_path, 'r') as ipa:
        info_plist_path = None
        for name in ipa.namelist():
            if 'Info.plist' in name:
                info_plist_path = name
                break

        if not info_plist_path:
            return None

        with ipa.open(info_plist_path) as info_plist_file:
            plist_data = info_plist_file.read()
            plist = plistlib.loads(plist_data)
            package_name = plist.get('CFBundleIdentifier')
            if not package_name:
                package_name = traverse_plist(plist)
            return package_name

def traverse_plist(plist):
    if isinstance(plist, dict):
        for key, value in plist.items():
            if key == 'CFBundleIdentifier':
                return value
            elif isinstance(value, dict):
                result = traverse_plist(value)
                if result:
                    return result
            elif isinstance(value, list):
                for item in value:
                    result = traverse_plist(item)
                    if result:
                        return result
    return None

@app.route('/')
def index():
    return render_template('index.html')
    

# Function to search for hardcoded secrets, URLs, emails, and credentials
def analyze_file(file_path):
    results = {
        'secrets': [],
        'urls': [],
        'emails': [],
        'credentials': []
    }

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()

        # Search for secrets
        secrets_regex = re.compile(r'(?:secret|token|key)\s*=\s*[\'"]([^\'"\\]*(?:\\.[^\'"\\]*)*)[\'"]', re.IGNORECASE)
        results['secrets'] = secrets_regex.findall(content)

        # Search for URLs
        urls_regex = re.compile(r'https?://\S+', re.IGNORECASE)
        results['urls'] = urls_regex.findall(content)

        # Search for emails
        emails_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        results['emails'] = emails_regex.findall(content)

        # Search for credentials (username-password pairs)
        credentials_regex = re.compile(r'(?:username|user|email|login)\s*[:=]\s*[\'"]([^\'"\\]*(?:\\.[^\'"\\]*)*)[\'"]\s*,?\s*(?:password|pass|passwd)\s*[:=]\s*[\'"]([^\'"\\]*(?:\\.[^\'"\\]*)*)[\'"]', re.IGNORECASE)
        credentials_matches = credentials_regex.findall(content)
        for match in credentials_matches:
            username = match[0]
            password = match[1]
            results['credentials'].append({'username': username, 'password': password})

    return results

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        md5_digest = md5_hash.hexdigest()
        sha256_digest = sha256_hash.hexdigest()

        if filename.endswith('.ipa'):
            package_name = extract_ipa_package_name(file_path)
            main_activity_name = None
        else:
            package_name, main_activity_name = extract_apk_info(file_path)

        # Run apkleaks command
        try:
            result = subprocess.run(['apkleaks', '-f', file_path], capture_output=True, text=True)
            output = result.stdout
            #print(output)  # Debug: Print the output from apkleaks

            # Parse the apkleaks output
            firebase = []
            google_api_key = []
            google_oauth = []
            linkfinder = []
            mailto = []
            amazon_AWS_S3_Bucket = []
            ip_address = []
            http_urls = []

            in_section = None
            for line in output.splitlines():
                line = line.strip()
                #print(f"Processing line: {line}")  # Debug: Print each line

                if line.startswith('[Firebase]'):
                    in_section = 'firebase'
                elif line.startswith('[Google_API_Key]'):
                    in_section = 'google_api_key'
                elif line.startswith('[Google_Cloud_Platform_OAuth]'):
                    in_section = 'google_oauth'
                elif line.startswith('[LinkFinder]'):
                    in_section = 'linkfinder'
                elif line.startswith('[Mailto]'):
                    in_section = 'mailto'
                elif line.startswith('[Amazon_AWS_S3_Bucket]'):
                    in_section = 'amazon_AWS_S3_Bucket'
                elif line.startswith('[IP_Address]'):
                    in_section = 'ip_address'
                elif line.startswith('['):
                    in_section = None
                elif in_section == 'firebase':
                    firebase_value = line.split('- ', 1)[1].strip() if '- ' in line else ''
                    firebase.append(firebase_value)
                elif in_section == 'google_api_key':
                    if not line.startswith('[92m'):
                        api_key_value = line.split('- ', 1)[1].strip() if '- ' in line else ''
                        google_api_key.append(api_key_value)
                elif in_section == 'google_oauth':
                    if not line.startswith('[92m'):
                        oauth_value = line.split('- ', 1)[1].strip() if '- ' in line else ''
                        google_oauth.append(oauth_value)
                elif in_section == 'linkfinder':
                    #link_value = line.split('-')[1].strip() if '-' in line else ''
                    link_value = line.split('- ', 1)[1].strip() if '- ' in line else ''
                    linkfinder.append(link_value)
                    if link_value.startswith('http://') or link_value.startswith('https://'):
                        http_urls.append(link_value)
                elif in_section == 'mailto':
                    if not line.startswith('[92m'):
                        mailto_value = line.split('- ', 1)[1].strip() if '- ' in line else ''
                        mailto.append(mailto_value)
                elif in_section == 'amazon_AWS_S3_Bucket':
                    if not line.startswith('[92m'):
                        amazon_Bucket_value = line.split('- ', 1)[1].strip() if '- ' in line else ''
                        amazon_AWS_S3_Bucket.append(amazon_Bucket_value)
                        #print(amazon_AWS_S3_Bucket)
                elif in_section == 'ip_address':
                    if not line.startswith('[92m'):
                        ip_address_value = line.split('- ', 1)[1].strip() if '- ' in line else ''
                        ip_address.append(ip_address_value)
	    
            analysis_results = analyze_file(file_path)
            #Sprint(f"Collected HTTP/HTTPS URLs: {http_urls}")

            return render_template('result.html', filename=filename, md5=md5_digest, sha256=sha256_digest, package_name=package_name, main_activity_name=main_activity_name, analysis_results=analysis_results, firebase=firebase, google_api_key=google_api_key, google_oauth=google_oauth, linkfinder=linkfinder, mailto=mailto, amazon_AWS_S3_Bucket=amazon_AWS_S3_Bucket, ip_address=ip_address,http_urls=http_urls ) 

        except Exception as e:
            return f'Error running apkleaks: {str(e)}'


def decode_apk_with_apktool(apk_file):
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'apktool_output')
    try:
        # Run apktool to decode the APK
        subprocess.run(['apktool', 'd', '-f', '-o', output_dir, apk_file], check=True)
        return output_dir
    except subprocess.CalledProcessError as e:
        print(f"Error decoding APK with apktool: {e}")
        return None

def read_manifest_xml(apktool_output_dir):
    manifest_path = os.path.join(apktool_output_dir, 'AndroidManifest.xml')
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        permissions = set()
        
        # Find all permission tags in the manifest
        for child in root.iter():
            if child.tag.endswith('uses-permission'):
                permission = child.attrib.get('{http://schemas.android.com/apk/res/android}name')
                if permission:
                    permissions.add(permission)
        
        return permissions
    except FileNotFoundError:
        print(f"AndroidManifest.xml not found in apktool output directory: {apktool_output_dir}")
        return None
    except Exception as e:
        print(f"Error reading AndroidManifest.xml: {e}")
        return None

def extract_permissions_from_content(manifest_content):
    permissions = set()
    permission_regex = r'android\.permission\.[A-Z_]+'
    for match in re.finditer(permission_regex, manifest_content):
        permissions.add(match.group())
    return permissions

@app.route('/view_manifest', methods=['POST'])
def view_main_activity():
    filename = request.form['filename']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Decode the APK using apktool
    apktool_output_dir = decode_apk_with_apktool(file_path)
    if not apktool_output_dir:
        return 'Failed to decode APK with apktool'
    
    # Read the AndroidManifest.xml from apktool output
    manifest_path = os.path.join(apktool_output_dir, 'AndroidManifest.xml')
    try:
        with open(manifest_path, 'r', encoding='utf-8') as manifest_file:
            manifest_content = manifest_file.read()
        
        # Extract permissions using regular expression
        permissions = extract_permissions_from_content(manifest_content)
        
        return render_template('view_manifest.html', aapt_output=manifest_content, permissions=list(permissions), manifest_path=manifest_path, permission_risk_level=permission_risk_level, risk_level_label=risk_level_label)
    
    except FileNotFoundError:
        return 'AndroidManifest.xml not found in apktool output directory'
    except Exception as e:
        return f'Error reading AndroidManifest.xml: {e}'

LOW_RISK_PERMISSIONS = [
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.WAKE_LOCK",
    "android.permission.VIBRATE"
]

MEDIUM_RISK_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE"
]

HIGH_RISK_PERMISSIONS = [
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN"
]

def permission_risk_level(permission):
    if permission in HIGH_RISK_PERMISSIONS:
        return "high-risk"
    elif permission in MEDIUM_RISK_PERMISSIONS:
        return "medium-risk"
    elif permission in LOW_RISK_PERMISSIONS:
        return "low-risk"
    else:
        return ""

def risk_level_label(permission):
    if permission in HIGH_RISK_PERMISSIONS:
        return "High Risk"
    elif permission in MEDIUM_RISK_PERMISSIONS:
        return "Medium Risk"
    elif permission in LOW_RISK_PERMISSIONS:
        return "Low Risk"
    else:
        return "Unknown Risk"


@app.route('/check_subdomain_vulnerability', methods=['POST'])
def check_subdomain_vulnerability_check():
    urls = request.form.get('urls')
    urls = json.loads(urls)
    processed_urls = list(set([urlparse(url).netloc for url in urls]))
    return render_template('subdomain_vulnerability_check.html', processed_urls=processed_urls)

@app.route('/check_OpenRedirect_vulnerability', methods=['POST'])
def check_OpenRedirect_vulnerability_check():
    urls = request.form.get('urls')
    urls = json.loads(urls)
    processed_urls = list(set([urlparse(url).netloc for url in urls]))
    return render_template('open_redirect_vulnerability_check.html', processed_urls=processed_urls)

@app.route('/check_LFI_vulnerability', methods=['POST'])
def check_LFI_check():
    urls = request.form.get('urls')
    urls = json.loads(urls)
    processed_urls = list(set([urlparse(url).netloc for url in urls]))
    return render_template('lfi_vulnerability_check.html', processed_urls=processed_urls)


@app.route('/check_SQLi_vulnerability', methods=['POST'])
def check_SQLi_check():
    urls = request.form.get('urls')
    urls = json.loads(urls)
    processed_urls = list(set([urlparse(url).netloc for url in urls]))
    return render_template('sqli_vulnerability_check.html', processed_urls=processed_urls)

@app.route('/run_subdomain_check', methods=['POST'])
def run_subdomain_check():
    subdomain = request.form['subdomain']
    if not subdomain:
        flash('Please enter a subdomain')
        return redirect(url_for('index'))

    try:
        result = subprocess.run(['python3', 'subdomain-tackover-check.py', subdomain], capture_output=True, text=True, check=True)
        output = result.stdout
        error_output = result.stderr

        # Parse the output into a list of tuples (subdomain, status)
        lines = output.splitlines()
        results = [line.split(': ') for line in lines]

    except subprocess.CalledProcessError as e:
        output = f"Error running subdomain check: {e.stdout}"
        error_output = e.stderr
        results = []

    return render_template('subdomain_check_result.html', subdomain=subdomain, results=results, error_output=error_output)

@app.route('/lfi_check', methods=['POST'])
def lfi_check():
    url = request.form['subdomain']
    if not url:
        flash('Please enter a URL')
        return redirect(url_for('index'))

    try:
        # Run the command with the input URL
        command = f"waybackurls {url} | uro | sed 's/=.*/=/' | gf lfi | nuclei -tags lfi"
        #print("Command:", command)
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        #print("Result:", result)
        output = result.stdout
        #print("Output:", output)

        # Extract URLs from the output
        urls = []
        lines = output.splitlines()
        for line in lines:
            # Find the last space in the line and get the URL part
            last_space_index = line.rfind(' ')
            if last_space_index != -1:
                extracted_url = line[last_space_index + 1:].strip()
                urls.append(extracted_url)

        return render_template('lfi_result.html', url=url, urls=urls)

    except Exception as e:
        return f'Error running LFI check: {str(e)}'

@app.route('/sqli_check', methods=['POST'])
def sqli_check():
    url = request.form['subdomain']
    if not url:
        flash('Please enter a URL')
        return redirect(url_for('index'))

    try:
        # Run the command with the input URL
        command = f"echo {url} | waybackurls > waybackurls_urls.txt ; python3 /home/kali/Project-data/SQLiDetector/sqlidetector.py -f waybackurls_urls.txt"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout
        error_output = result.stderr

        if error_output:
            return f"Error running command: {error_output}"

        # Filter the output to exclude the banner and unnecessary lines
        filtered_output = []
        for line in output.splitlines():
            if not line.startswith("+-") and not line.startswith("|") and not line.startswith(">"):
                filtered_output.append(line)
        
        filtered_output = "\n".join(filtered_output)

        return render_template('sqli_vulnerability_result.html', url=url, output=filtered_output)

    except Exception as e:
        return f'Error running SQLi check: {str(e)}'

@app.route('/open_redirect_check', methods=['POST'])
def open_redirect_check():
    url = request.form['url']
    if not url:
        flash('Please enter a URL')
        return redirect(url_for('index'))

    try:
        # Run the command with the input URL
        command = f"waybackurls {url} | tee {url}-waybackURL.txt | grep =http"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout
        error_output = result.stderr

        if error_output:
            return f"Error running command: {error_output}"

        return render_template('open_redirect_result.html', url=url, output=output)

    except Exception as e:
        return f'Error running Open Redirect check: {str(e)}'

@app.route('/open_redirect_POC_check', methods=['POST'])
def open_redirect_POC_check():
    url = request.form.get('subdomain')
    if not url:
        flash('Please enter a URL')
        return redirect(url_for('index'))

    try:
        # Run the command with the input URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        command = f"python3 webster.py -u {url} -w {domain} -p payloads.txt -t 2"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout
        error_output = result.stderr

        if error_output:
            return f"Error running command: {error_output}"

        # Process the output to filter and format vulnerable URLs
        vulnerable_urls = []
        lines = output.splitlines()
        for line in lines:
            if line.startswith("\x1b[31mVulnerable "):
                parts = line.split(" ")
                if len(parts) >= 2:
                    vulnerable_url = " ".join(parts[1:])
                    vulnerable_urls.append(vulnerable_url.strip())

        return render_template('open_redirect_POC_result.html', url=url, vulnerable_urls=vulnerable_urls)

    except Exception as e:
        return f'Error running Open Redirect check: {str(e)}'

@app.route('/check_urls_vulnerability', methods=['POST'])
def check_urls_vulnerability():
    urls = request.form.get('urls')
    urls = json.loads(urls)
    return render_template('check_urls_vulnerability.html', urls=urls)

@app.route('/check_vulnerabilities', methods=['POST'])
def check_vulnerabilities():
    manifest_path = request.form['manifest_path']
    
    if not manifest_path:
        return 'Manifest path is empty'
    
    # Run the vulnerability check script and capture the output
    try:
        result = subprocess.run(
            ['python3', 'Manifest-Vulnerability-check.py', manifest_path], 
            capture_output=True, text=True, check=True
        )
        output = result.stdout
        error_output = result.stderr

        # Debug output
        print("Script output:", output)
        print("Script error output:", error_output)

    except subprocess.CalledProcessError as e:
        output = f"Error running vulnerability check: {e}"
        error_output = e.stderr
        print("Exception output:", error_output)
    
    return render_template('vulnerability_result.html', output=output)

      
@app.route('/view_strings', methods=['POST'])
def view_strings():
    filename = request.form['filename']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if filename.endswith('.ipa'):
        try:
            strings_output = subprocess.check_output(['strings', file_path]).decode('utf-8')
            return render_template('view_strings.html', filename=filename, strings_output=strings_output)
        except subprocess.CalledProcessError:
            return 'Failed to retrieve strings information'
    elif filename.endswith('.apk'):
        try:
            aapt_output = subprocess.check_output(['aapt', 'd', '--values', 'strings', file_path]).decode('utf-8')
            return render_template('view_strings.html', filename=filename, strings_output=aapt_output)
        except subprocess.CalledProcessError:
            return 'Failed to retrieve strings information'
    else:
        return 'Unsupported file format'

@app.route('/view_info_plist', methods=['POST'])
def view_info_plist():
    filename = request.form['filename']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if filename.endswith('.ipa'):
        try:
            temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_extract')
            os.makedirs(temp_dir, exist_ok=True)
            
            with zipfile.ZipFile(file_path, 'r') as ipa:
                ipa.extractall(temp_dir)
            
            plist_path_in_temp = None
            payload_dir = os.path.join(temp_dir, 'Payload')
            for root, dirs, files in os.walk(payload_dir):
                for file in files:
                    if file == 'Info.plist':
                        plist_path_in_temp = os.path.join(root, file)
                        break
                if plist_path_in_temp:
                    break
            
            if plist_path_in_temp:
                with open(plist_path_in_temp, 'rb') as plist_file:
                    plist_data = plist_file.read()
                    plist_xml = plistlib.loads(plist_data)
                    plist_xml_str = plistlib.dumps(plist_xml)
                    decoded_output = plist_xml_str.decode('utf-8')
                    
                    found_permissions = find_permissions(plist_xml)
                    
                    return render_template('info_plist.html', filename=filename, plist_xml_str=decoded_output, permissions=found_permissions)
            else:
                return 'Info.plist not found in the IPA file'
        except Exception as e:
            return f'Error: {str(e)}'
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    else:
        return 'This functionality is only available for IPA files'

# Function to find and return permissions from Info.plist
def find_permissions(plist_xml):
    permissions_to_search = {
        'NSCameraUsageDescription': 'high',
        'NSPhotoLibraryUsageDescription': 'medium',
        'NSMicrophoneUsageDescription': 'high',
        'NSLocationWhenInUseUsageDescription': 'high',
        'NSLocationAlwaysUsageDescription': 'high',
        'NSLocationAlwaysAndWhenInUseUsageDescription': 'high',
        'NSContactsUsageDescription': 'high',
        'NSCalendarsUsageDescription': 'medium',
        'NSRemindersUsageDescription': 'medium',
        'NSMotionUsageDescription': 'low',
        'NSHealthShareUsageDescription': 'high',
        'NSHealthUpdateUsageDescription': 'high',
        'NSBluetoothAlwaysUsageDescription': 'medium',
        'NSBluetoothPeripheralUsageDescription': 'medium',
        'NSFaceIDUsageDescription': 'high',
        'NSSpeechRecognitionUsageDescription': 'high'
    }
    
    found_permissions = []
    for key in plist_xml.keys():
        if key in permissions_to_search:
            found_permissions.append({'name': key, 'risk': permissions_to_search[key]})
    
    return found_permissions

@app.route('/check_api_vulnerability', methods=['POST'])
def check_api_vulnerability():
    try:
        api_key = request.form['api_key']
        
        # Run the vulnerability scanner script with the provided API key
        result = subprocess.run(['python3', 'maps_api_scanner.py', '--api-key', api_key], capture_output=True, text=True)
        output = result.stdout.strip()  # Get the output from the subprocess

        #print("Output from maps_api_scanner.py:")
        #print(output)  # Print the output for debugging purposes

        # Pass the output and api_key to the template
        return render_template('api_vulnerability_result.html', output=output, apikey=api_key)
    
    except Exception as e:
        return f'Error running API vulnerability check: {str(e)}'

@app.route('/check_info_plist_vulnerabilities', methods=['POST'])
def check_info_plist_vulnerabilities():
    filename = request.form['filename']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_extract')
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        with zipfile.ZipFile(file_path, 'r') as ipa:
            ipa.extractall(temp_dir)
        
        plist_path_in_temp = None
        payload_dir = os.path.join(temp_dir, 'Payload')
        for root, dirs, files in os.walk(payload_dir):
            for file in files:
                if file == 'Info.plist':
                    plist_path_in_temp = os.path.join(root, file)
                    break
            if plist_path_in_temp:
                break
        
        if not plist_path_in_temp or not os.path.exists(plist_path_in_temp):
            return f"Error: The path '{plist_path_in_temp}' does not exist."
        
        try:
            result = subprocess.run(
                ['python3', 'check_info_plist.py', plist_path_in_temp], 
                capture_output=True, text=True, check=True
            )
            output = result.stdout
            error_output = result.stderr

            print("Script output:", output)
            print("Script error output:", error_output)

        except subprocess.CalledProcessError as e:
            output = f"Error running vulnerability check: {e}"
            error_output = e.stderr
            print("Exception output:", error_output)
        
        return render_template('vulnerability_results.html', output=output + "\n\nError Output:\n" + error_output)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)



    
if __name__ == '__main__':
    app.run(debug=True)
