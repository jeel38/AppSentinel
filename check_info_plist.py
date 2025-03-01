import plistlib
import sys

def check_vulnerabilities(plist_path):
    with open(plist_path, 'rb') as f:
        plist = plistlib.load(f)

    vulnerabilities = []

    # Example vulnerability checks:

    # 1. Check for the presence of `NSAllowsArbitraryLoads` in `NSAppTransportSecurity` (ATS)
    ats = plist.get('NSAppTransportSecurity', {})
    if ats.get('NSAllowsArbitraryLoads', False):
        vulnerabilities.append("NSAllowsArbitraryLoads is enabled. This allows arbitrary loads, which can be a security risk.")

    # 2. Check if `UIFileSharingEnabled` is enabled
    if plist.get('UIFileSharingEnabled', False):
        vulnerabilities.append("UIFileSharingEnabled is enabled. This allows users to access the app's Documents folder via iTunes, which can be a security risk.")

    # 3. Check if `LSSupportsOpeningDocumentsInPlace` is enabled
    if plist.get('LSSupportsOpeningDocumentsInPlace', False):
        vulnerabilities.append("LSSupportsOpeningDocumentsInPlace is enabled. This allows documents to be opened in place, which can be a security risk if not handled correctly.")

    # 4. Check if `NSLocationAlwaysUsageDescription` or `NSLocationWhenInUseUsageDescription` are missing
    if 'NSLocationAlwaysUsageDescription' not in plist and 'NSLocationWhenInUseUsageDescription' not in plist:
        vulnerabilities.append("Location usage descriptions are missing. This can result in the app being rejected by the App Store.")

    # 5. Check for usage of `UIBackgroundModes` for unnecessary background tasks
    background_modes = plist.get('UIBackgroundModes', [])
    if background_modes:
        vulnerabilities.append(f"UIBackgroundModes is set to {background_modes}. Ensure these background modes are necessary and handled securely.")

    # 6. Check if `NSAllowsArbitraryLoadsInWebContent` is enabled
    if ats.get('NSAllowsArbitraryLoadsInWebContent', False):
        vulnerabilities.append("NSAllowsArbitraryLoadsInWebContent is enabled. This allows arbitrary loads in web content, which can be a security risk.")

    # 7. Check if `UIRequiresFullScreen` is set to False
    if plist.get('UIRequiresFullScreen', True) is False:
        vulnerabilities.append("UIRequiresFullScreen is set to False. This allows the app to run in split view, which might not be desirable for all apps.")

    # 8. Check if `ITSAppUsesNonExemptEncryption` is missing
    if 'ITSAppUsesNonExemptEncryption' not in plist:
        vulnerabilities.append("ITSAppUsesNonExemptEncryption is missing. This key is required to indicate if the app uses encryption.")

    # 9. Check if `NSCameraUsageDescription` is missing
    if 'NSCameraUsageDescription' not in plist:
        vulnerabilities.append("NSCameraUsageDescription is missing. This key is required to access the camera.")

    # 10. Check if `NSPhotoLibraryUsageDescription` is missing
    if 'NSPhotoLibraryUsageDescription' not in plist:
        vulnerabilities.append("NSPhotoLibraryUsageDescription is missing. This key is required to access the photo library.")

    # 11. Check if `NSMicrophoneUsageDescription` is missing
    if 'NSMicrophoneUsageDescription' not in plist:
        vulnerabilities.append("NSMicrophoneUsageDescription is missing. This key is required to access the microphone.")

    # 12. Check if `NSCalendarsUsageDescription` is missing
    if 'NSCalendarsUsageDescription' not in plist:
        vulnerabilities.append("NSCalendarsUsageDescription is missing. This key is required to access calendars.")

    # 13. Check if `NSContactsUsageDescription` is missing
    if 'NSContactsUsageDescription' not in plist:
        vulnerabilities.append("NSContactsUsageDescription is missing. This key is required to access contacts.")

    # 14. Check if `NSBluetoothAlwaysUsageDescription` or `NSBluetoothPeripheralUsageDescription` are missing
    if 'NSBluetoothAlwaysUsageDescription' not in plist and 'NSBluetoothPeripheralUsageDescription' not in plist:
        vulnerabilities.append("Bluetooth usage descriptions are missing. This can result in the app being rejected by the App Store.")

    # 15. Check if `NSHealthUpdateUsageDescription` or `NSHealthShareUsageDescription` are missing
    if 'NSHealthUpdateUsageDescription' not in plist and 'NSHealthShareUsageDescription' not in plist:
        vulnerabilities.append("Health data usage descriptions are missing. This can result in the app being rejected by the App Store.")

    return vulnerabilities

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python check_info_plist.py <path_to_info.plist>")
        sys.exit(1)

    plist_path = sys.argv[1]
    vulnerabilities = check_vulnerabilities(plist_path)

    if vulnerabilities:
        print("Found the following vulnerabilities:")
        for vulnerability in vulnerabilities:
            print(f"- {vulnerability}")
    else:
        print("No vulnerabilities found.")
