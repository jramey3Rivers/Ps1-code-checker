@echo off

echo This script is for onboarding machines to the Microsoft Defender for Endpoint services, including security and compliance products.
echo Once completed, the machine should light up in the portal within 5-30 minutes, depending on this machine's Internet connectivity availability and machine power state (plugged in vs. battery powered).
echo IMPORTANT: This script is optimized for onboarding a single machine and should not be used for large scale deployment.
echo For more information on large scale deployment, please consult the MDE documentation (links available in the MDE portal under the endpoint onboarding section).

# Check if running as Administrator
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Script is not running as Administrator. Attempting to restart with elevated privileges."
    
    # Re-launch the script with Administrator privileges
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    
    # Exit the current script
    Exit
}

Write-Output "Script is running with Administrator privileges."
echo.

:SCRIPT_START
%windir%\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v latency /t REG_SZ /f /d "Demo" >NUL 2>&1

@echo off

echo.
echo Starting Microsoft Defender for Endpoint onboarding process...
echo.

set errorCode=0
set lastError=0
set "troubleshootInfo=For more information, visit: https://go.microsoft.com/fwlink/p/?linkid=822807"
set "errorDescription="

echo Testing administrator privileges

%windir%\System32\net.exe session >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
    @echo Script is running with insufficient privileges. Please run with administrator privileges> %WINDIR%\temp\senseTmp.txt
    set errorCode=65
    set lastError=%ERRORLEVEL%
    GOTO ERROR
)

echo Script is running with sufficient privileges
echo.
echo Performing onboarding operations
echo.

IF [%PROCESSOR_ARCHITEW6432%] EQU [] (
  set powershellPath=%windir%\System32\WindowsPowerShell\v1.0\powershell.exe
) ELSE (
  set powershellPath=%windir%\SysNative\WindowsPowerShell\v1.0\powershell.exe
)

set sdbin=0100048044000000540000000000000014000000020030000200000000001400FF0F120001010000000000051200000000001400E104120001010000000000050B0000000102000000000005200000002002000001020000000000052000000020020000 >NUL 2>&1
%windir%\System32\reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Security /v 14f8138e-3b61-580b-544b-2609378ae460 /t REG_BINARY /d %sdbin% /f >NUL 2>&1
%windir%\System32\reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Security /v cb2ff72d-d4e4-585d-33f9-f3a395c40be7 /t REG_BINARY /d %sdbin% /f >NUL 2>&1

%windir%\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableEnterpriseAuthProxy /t REG_DWORD /f /d 1 >NUL 2>&1

%powershellPath% -ExecutionPolicy Bypass -NoProfile -Command "Add-Type ' using System; using System.IO; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles; using System.ComponentModel; public static class Elam{ [DllImport(\"Kernel32\", CharSet=CharSet.Auto, SetLastError=true)] public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle); public static void InstallWdBoot(string path) { Console.Out.WriteLine(\"About to call create file on {0}\", path); var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read); var handle = stream.SafeFileHandle; Console.Out.WriteLine(\"About to call InstallELAMCertificateInfo on handle {0}\", handle.DangerousGetHandle()); if (!InstallELAMCertificateInfo(handle)) { Console.Out.WriteLine(\"Call failed.\"); throw new Win32Exception(Marshal.GetLastWin32Error()); } Console.Out.WriteLine(\"Call successful.\"); } } '; $driverPath = $env:SystemRoot + '\System32\Drivers\WdBoot.sys'; [Elam]::InstallWdBoot($driverPath) " >NUL 2>&1

%windir%\System32\reg.exe query "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v 696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A /reg:64 > %WINDIR%\temp\senseTmp.txt 2>&1
if %ERRORLEVEL% EQU 0 (  
    %windir%\System32\reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v 696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A /f > %WINDIR%\temp\senseTmp.txt 2>&1
    if %ERRORLEVEL% NEQ 0 (
        set "errorDescription=Unable to delete previous offboarding information from registry."
        set errorCode=5
        set lastError=%ERRORLEVEL%
        GOTO ERROR
    )
)

%windir%\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v OnboardingInfo /t REG_SZ /f /d "{\"body\":\"{\\\"previousOrgIds\\\":[],\\\"orgId\\\":\\\"baa9e42e-6fc9-42ce-8264-7939f2e1c3d0\\\",\\\"geoLocationUrl\\\":\\\"https://edr-cus3.us.endpoint.security.microsoft.com/edr/\\\",\\\"datacenter\\\":\\\"CentralUs3\\\",\\\"vortexGeoLocation\\\":\\\"US\\\",\\\"vortexServerUrl\\\":\\\"https://us-v20.events.endpoint.security.microsoft.com/OneCollector/1.0\\\",\\\"vortexTicketUrl\\\":\\\"https://events.data.microsoft.com\\\",\\\"partnerGeoLocation\\\":\\\"GW_US\\\",\\\"version\\\":\\\"1.7\\\"}\",\"sig\":\"qePYrjNgC21QqUOgwC1af1mQFr806BwJoveqZjQ4YtNBzIL4ey2Xz+7LiVfUmTfX8HjS1USEADfP/sllOu3ikbbf4+cHHBNEl0oonPA6WWkvqMeweeo6Lvy+HZ3vQ8yMQyy1d/sjyFakDtZucWWJmPFkPxEg1mizUy/DZwFt0eFtir9ekf5zWL2TwCsk3dYdolj+BSc/GY7aj9wGtrq5DxkYd9vrPW4MOABpYqM+DiKsQnY4H/FRAa2pLPNY5K/2MkmxQJ9rvFYitlZoVBzzHqLzUiPnSSR5F0B02k8Xaxr8bH9zZDwpXerK6HDDCkMszRu+xTvlga723064C6Izng==\",\"sha256sig\":\"qePYrjNgC21QqUOgwC1af1mQFr806BwJoveqZjQ4YtNBzIL4ey2Xz+7LiVfUmTfX8HjS1USEADfP/sllOu3ikbbf4+cHHBNEl0oonPA6WWkvqMeweeo6Lvy+HZ3vQ8yMQyy1d/sjyFakDtZucWWJmPFkPxEg1mizUy/DZwFt0eFtir9ekf5zWL2TwCsk3dYdolj+BSc/GY7aj9wGtrq5DxkYd9vrPW4MOABpYqM+DiKsQnY4H/FRAa2pLPNY5K/2MkmxQJ9rvFYitlZoVBzzHqLzUiPnSSR5F0B02k8Xaxr8bH9zZDwpXerK6HDDCkMszRu+xTvlga723064C6Izng==\",\"cert\":\"MIIFgzCCA2ugAwIBAgITMwAAAwiuH9Ak1Zb1UAAAAAADCDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAyMDExMB4XDTI0MDgyMjIwMDYwOVoXDTI1MDgyMjIwMDYwOVowHjEcMBoGA1UEAxMTU2V2aWxsZS5XaW5kb3dzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5GSnNoBWBUybDN/NOY+j+X4jpWFU84ZKKhoLD3JX1vcDBKId/o0xOoKVMIqcDGmdsX6Fjit2XssI9wHXvKiJdk/v9SQhJYhG3tFoip9+RmK+DPn3lMKDJx6KHhd/AIlMmp+4Ma433+BmDgMAIvbZDm1xRH4t9SwKlvBBwoQEs4zR0Nbz/aEkL7rD1CHIjIt++hGUQ4VRLnS4RUVXwIuFzvKiBnAR3WSbW0vVr5nU6al/WSinxJ+sLglC1aWWLO3EAGHrN4Ohnm5JK7lqEmbNyv7W6KOyFqnKfiDrk/DsUD0SJycoPNleRnJRTfbb6Rfmpbyr+bOt8yL27YF+crC/0CAwEAAaOCAVgwggFUMA4GA1UdDwEB/wQEAwIFIDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAeBgNVHREEFzAVghNTZXZpbGxlLldpbmRvd3MuY29tMB0GA1UdDgQWBBQC/j4kVANjV6pF/RIxeCyCfnEKnDAfBgNVHSMEGDAWgBQ2VollSctbmy88rEIWUE2RuTPXkTBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNTZWNTZXJDQTIwMTFfMjAxMS0xMC0xOC5jcmwwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzAChkRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY1NlY1NlckNBMjAxMV8yMDExLTEwLTE4LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAQy6ejw037hwXvDPZF1WzHp/K0XxSHqr2WpixK3X3DHLuvcWaZJR8PhrsQGnjt+4epxrPaGdYgbj7TRLkFeKtUKiQIVfG7wbAXahHcknqhRkrI0LvWTfmLZtc4I2YXdEuKOnRoRIcbOT9NKBvc7N1jqweFPX7/6K4iztP9fyPhrwIHl544uOSRcrTahpO80Bmpz8n/WEVNQDc+ie+LI78adJh+eoiGzCgXSNhc8QbTKMZXIhzRIIf1fRKkAQxbdsjb/6kQ1hQ0u5RCd/eFCWODuCfpOAevJkn0rHmEzutbbFps/QdWwLyIj1HE+qTv5dNpYUx0oEGYtc83EIbGFZZyfrB6iDQvainmVp82La+Ahtw4+guVBLTSE7HKudob78WHX4WKBzJBKWUBlHM/lm67Qus28oU144qFMtsOg/rfN3J1J1ydT0GfulGJ8MR0+qJ9pk6ojv0W+F4mwuqkMWQuNAH9BL+5NkghtwBL0BwHpNyFtXzXiNf6s+cYuKGQsS4/ku4eczk/NRWryfXGjGM23zrpIsLkr5DCer34gjdTwn2TmQbWt+65pYyCpFc53v3ejCyTLz13O6JOFuXkL4K9QRqak9xtiGZik6EgTzKE4Ve6SIRFluxleV4UQ3XdzLb+903YD2Ke57PCpBHq/x35xcn+DzHVU3S2C/i43wUeKo=\",\"chain\":[\"MIIG2DCCBMCgAwIBAgIKYT+3GAAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTExMDE4MjI1NTE5WhcNMjYxMDE4MjMwNTE5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0AvApKgZgeI25eKq5fOyFVh1vrTlSfHghPm7DWTvhcGBVbjz5/FtQFU9zotq0YST9XV8W6TUdBDKMvMj067uz54EWMLZR8vRfABBSHEbAWcXGK/G/nMDfuTvQ5zvAXEqH4EmQ3eYVFdznVUr8J6OfQYOrBtU8yb3+CMIIoueBh03OP1y0srlY8GaWn2ybbNSqW7prrX8izb5nvr2HFgbl1alEeW3Utu76fBUv7T/LGy4XSbOoArX35Ptf92s8SxzGtkZN1W63SJ4jqHUmwn4ByIxcbCUruCw5yZEV5CBlxXOYexl4kvxhVIWMvi1eKp+zU3sgyGkqJu+mmoE4KMczVYYbP1rL0I+4jfycqvQeHNye97sAFjlITCjCDqZ75/D93oWlmW1w4Gv9DlwSa/2qfZqADj5tAgZ4Bo1pVZ2Il9q8mmuPq1YRk24VPaJQUQecrG8EidT0sH/ss1QmB619Lu2woI52awb8jsnhGqwxiYL1zoQ57PbfNNWrFNMC/o7MTd02Fkr+QB5GQZ7/RwdQtRBDS8FDtVrSSP/z834eoLP2jwt3+jYEgQYuh6Id7iYHxAHu8gFfgsJv2vd405bsPnHhKY7ykyfW2Ip98eiqJWIcCzlwT88UiNPQJrDMYWDL78p8R1QjyGWB87v8oDCRH2bYu8vw3eJq0VNUz4CedMCAwEAAaOCAUswggFHMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBQ2VollSctbmy88rEIWUE2RuTPXkTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVH