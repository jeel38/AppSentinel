import zipfile
import re
import os

# Function to extract an IPA file
def extract_ipa(ipa_path, extract_dir):
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

# Function to search for sensitive information
def find_sensitive_info(extract_dir):
    sensitive_patterns = {
        'URLs': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        'Emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'Hardcoded Secrets': r'(?:secret|password|token)\s*=\s*[\'"][^\'"]+[\'"]',
        'Firebase URLs': r'https://[-\w]+\.firebaseio\.com',
        'IP Addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'Google API Keys': r'AIza[0-9A-Za-z_-]{35}',
        'Google OAuth Tokens': r'ya29\.[0-9A-Za-z_-]+',
        'AWS S3 Buckets': r's3://([a-zA-Z0-9.-]+)/?',
    }

    results = {key: [] for key in sensitive_patterns.keys()}

    for root, _, files in os.walk(extract_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()
                    for pattern_name, pattern in sensitive_patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            results[pattern_name].extend(matches)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")

    return results

# Main function to process IPA file
def process_ipa(ipa_path):
    extract_dir = os.path.splitext(ipa_path)[0]
    extract_ipa(ipa_path, extract_dir)
    sensitive_info = find_sensitive_info(extract_dir)
    return sensitive_info

# Example usage
if __name__ == "__main__":
    ipa_path = '/home/kali/Desktop/sg.com.hsbc.hsbcsingapore-3.43.0.ipa'  # Replace with your IPA file path
    sensitive_info = process_ipa(ipa_path)
    
    print("Sensitive information found:")
    for category, items in sensitive_info.items():
        if items:
            print(f"{category}:")
            for item in items:
                print(f"  - {item}")
