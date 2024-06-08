import tkinter as tk
from tkinter import messagebox
import subprocess

def run_powershell_command(command):
    try:
        subprocess.run(["powershell", "-Command", command], check=True, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        print(e)
        return False

def protect_privacy():
    commands = [
        '$Advertising = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo"; ' \
        'If (Test-Path $Advertising) { Set-ItemProperty $Advertising Enabled -Value 0 }',
        '$Search = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"; ' \
        'If (Test-Path $Search) { Set-ItemProperty $Search AllowCortana -Value 0 }',
        'Set-ItemProperty "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" BingSearchEnabled -Value 0',
        '$WebSearch = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"; ' \
        'If (!(Test-Path $WebSearch)) { New-Item $WebSearch }; ' \
        'Set-ItemProperty $WebSearch DisableWebSearch -Value 1',
        '$Period = "HKCU:\\Software\\Microsoft\\Siuf\\Rules"; ' \
        'If (!(Test-Path $Period)) { New-Item $Period }; ' \
        'Set-ItemProperty $Period PeriodInNanoSeconds -Value 0',
        '$registryPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent"; ' \
        'If (!(Test-Path $registryPath)) { New-Item $registryPath }; ' \
        'Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1',
        '$registryOEM = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager"; ' \
        'If (!(Test-Path $registryOEM)) { New-Item $registryOEM }; ' \
        'Set-ItemProperty $registryOEM ContentDeliveryAllowed -Value 0; ' \
        'Set-ItemProperty $registryOEM OemPreInstalledAppsEnabled -Value 0; ' \
        'Set-ItemProperty $registryOEM PreInstalledAppsEnabled -Value 0; ' \
        'Set-ItemProperty $registryOEM PreInstalledAppsEverEnabled -Value 0; ' \
        'Set-ItemProperty $registryOEM SilentInstalledAppsEnabled -Value 0; ' \
        'Set-ItemProperty $registryOEM SystemPaneSuggestionsEnabled -Value 0',
        '$Holo = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Holographic"; ' \
        'If (Test-Path $Holo) { Set-ItemProperty $Holo FirstRunSucceeded -Value 0 }',
        '$WifiSense1 = "HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting"; ' \
        'If (!(Test-Path $WifiSense1)) { New-Item $WifiSense1 }; ' \
        'Set-ItemProperty $WifiSense1 Value -Value 0',
        '$WifiSense2 = "HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots"; ' \
        'If (!(Test-Path $WifiSense2)) { New-Item $WifiSense2 }; ' \
        'Set-ItemProperty $WifiSense2 Value -Value 0',
        '$WifiSense3 = "HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config"; ' \
        'Set-ItemProperty $WifiSense3 AutoConnectAllowedOEM -Value 0',
        '$Live = "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications"; ' \
        'If (!(Test-Path $Live)) { New-Item $Live }; ' \
        'Set-ItemProperty $Live NoTileApplicationNotification -Value 1',
        '$DataCollection1 = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection"; ' \
        'If (Test-Path $DataCollection1) { Set-ItemProperty $DataCollection1 AllowTelemetry -Value 0 }',
        '$DataCollection2 = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"; ' \
        'If (Test-Path $DataCollection2) { Set-ItemProperty $DataCollection2 AllowTelemetry -Value 0 }',
        '$DataCollection3 = "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection"; ' \
        'If (Test-Path $DataCollection3) { Set-ItemProperty $DataCollection3 AllowTelemetry -Value 0 }',
        '$SensorState = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Overrides\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"; ' \
        'If (!(Test-Path $SensorState)) { New-Item $SensorState }; ' \
        'Set-ItemProperty $SensorState SensorPermissionState -Value 0',
        '$LocationConfig = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration"; ' \
        'If (!(Test-Path $LocationConfig)) { New-Item $LocationConfig }; ' \
        'Set-ItemProperty $LocationConfig Status -Value 0',
        '$People = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People"; ' \
        'If (Test-Path $People) { Set-ItemProperty $People -Name PeopleBand -Value 0 }'
    ]

    success_count = 0
    for command in commands:
        if run_powershell_command(command):
            success_count += 1

    return success_count

def disable_cortana():
    commands = [
        '$Cortana1 = "HKCU:\\SOFTWARE\\Microsoft\\Personalization\\Settings"; ' \
        'If (!(Test-Path $Cortana1)) { New-Item $Cortana1 }; ' \
        'Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0',
        '$Cortana2 = "HKCU:\\SOFTWARE\\Microsoft\\InputPersonalization"; ' \
        'If (!(Test-Path $Cortana2)) { New-Item $Cortana2 }; ' \
        'Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1; ' \
        'Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1',
        '$Cortana3 = "HKCU:\\SOFTWARE\\Microsoft\\InputPersonalization\\TrainedDataStore"; ' \
        'If (!(Test-Path $Cortana3)) { New-Item $Cortana3 }; ' \
        'Set-ItemProperty $Cortana3 HarvestContacts -Value 0'
    ]

    success_count = 0
    for command in commands:
        if run_powershell_command(command):
            success_count += 1

    return success_count

def stop_edge_pdf():
    command = '''
    $NoPDF = "HKCR:\\.pdf";
    $NoProgids = "HKCR:\\.pdf\\OpenWithProgids";
    $NoWithList = "HKCR:\\.pdf\\OpenWithList";
    If (!(Get-ItemProperty $NoPDF NoOpenWith)) { New-ItemProperty $NoPDF NoOpenWith };
    If (!(Get-ItemProperty $NoPDF NoStaticDefaultVerb)) { New-ItemProperty $NoPDF NoStaticDefaultVerb };
    If (!(Get-ItemProperty $NoProgids NoOpenWith)) { New-ItemProperty $NoProgids NoOpenWith };
    If (!(Get-ItemProperty $NoProgids NoStaticDefaultVerb)) { New-ItemProperty $NoProgids NoStaticDefaultVerb };
    If (!(Get-ItemProperty $NoWithList NoOpenWith)) { New-ItemProperty $NoWithList NoOpenWith };
    If (!(Get-ItemProperty $NoWithList NoStaticDefaultVerb)) { New-ItemProperty $NoWithList NoStaticDefaultVerb };
    $Edge = "HKCR:\\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_";
    If (Test-Path $Edge) { Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_ };
    '''
    if run_powershell_command(command):
        return 1
    else:
        return 0

def check_dmw_service():
    command = '''
    If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
        Set-Service -Name dmwappushservice -StartupType Automatic
    }
    If (Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
        Start-Service -Name dmwappushservice
    }
    '''
    if run_powershell_command(command):
        return 1
    else:
        return 0

def remove_3d_objects():
    command = '''
    $Objects32 = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}";
    $Objects64 = "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}";
    If (Test-Path $Objects32) { Remove-Item $Objects32 -Recurse };
    If (Test-Path $Objects64) { Remove-Item $Objects64 -Recurse };
    '''
    if run_powershell_command(command):
        return 1
    else:
        return 0

def show_success_message(message):
    popup = tk.Toplevel()
    popup.title("Success")
    label = tk.Label(popup, text=message)
    label.pack(padx=20, pady=10)
    ok_button = tk.Button(popup, text="OK", command=popup.destroy)
    ok_button.pack(pady=10)

def execute_protect_privacy():
    success_count = protect_privacy()
    message = f"{success_count} privacy protection commands executed successfully."
    show_success_message(message)

def execute_disable_cortana():
    success_count = disable_cortana()
    message = f"{success_count} Cortana disabling commands executed successfully."
    show_success_message(message)

def execute_stop_edge_pdf():
    success_count = stop_edge_pdf()
    message = f"{success_count} Edge PDF stopping commands executed successfully."
    show_success_message(message)

def execute_check_dmw_service():
    success_count = check_dmw_service()
    if success_count == 1:
        message = "DMWAppPushService has been started and set to Automatic startup."
    else:
        message = "DMWAppPushService is either stopped or disabled."
    show_success_message(message)

def execute_remove_3d_objects():
    success_count = remove_3d_objects()
    message = f"{success_count} 3D Objects removal commands executed successfully."
    show_success_message(message)

def main():
    root = tk.Tk()
    root.title("Windows Debloat Tool")
    root.geometry("600x600")
    root.iconbitmap("logo.ico")

    protect_privacy_button = tk.Button(root, text="Protect Privacy", command=execute_protect_privacy)
    protect_privacy_button.pack(pady=10)

    disable_cortana_button = tk.Button(root, text="Disable Cortana", command=execute_disable_cortana)
    disable_cortana_button.pack(pady=10)

    stop_edge_pdf_button = tk.Button(root, text="Stop Edge PDF", command=execute_stop_edge_pdf)
    stop_edge_pdf_button.pack(pady=10)

    check_dmw_service_button = tk.Button(root, text="Check DMW Service", command=execute_check_dmw_service)
    check_dmw_service_button.pack(pady=10)

    remove_3d_objects_button = tk.Button(root, text="Remove 3D Objects", command=execute_remove_3d_objects)
    remove_3d_objects_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
