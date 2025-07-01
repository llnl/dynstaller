## Installing Windows Sandbox

Instructions are provided by Microsoft [here](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install). Otherwise, open a PowerShell terminal as an administrator and run the following command:
```powershell
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
```

## Running Windows Sandbox

To run a .wsb (Windows Sandbox configuration file), you can double-click the file in File Explorer or pass it via command line:
```
"C:\Windows\System32\WindowsSandbox.exe" "C:\path\to\your\file.wsb"
```