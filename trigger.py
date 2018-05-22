import ctypes
import inspect
import os
import os.path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import winreg

##
## Function Name:
##   has_admin()
##
## Purpose:
##   Checks if user has admin privileges
##
## References:
##   https://stackoverflow.com/questions/2946746/python-checking-if-a-user-has-administrator-privileges
##
def has_admin():
    if os.name == 'nt':
        try:
            # only windows users with admin privileges can read the C:\windows\temp
            temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
        except:
            return (os.environ['USERNAME'],False)
        else:
            return (os.environ['USERNAME'],True)
    else:
        if 'SUDO_USER' in os.environ and os.geteuid() == 0:
            return (os.environ['SUDO_USER'],True)
        else:
            return (os.environ['USERNAME'],False)

##
## Function Name:
##   trigger1()
##
## Purpose:
##   Triggers Sysmon Event ID 1
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 1: Process creation
##     The process creation event provides extended information about a newly created process.
##     The full command line provides context on the process execution.
##     The ProcessGUID field is a unique value for this process across a domain to make event correlation easier.
##     The hash is a full hash of the file with the algorithms in the HashType field.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <ProcessCreate onmatch="exclude">
##	<!--COMMENT:	All process launched will be included, except for what matches a rule below... Make sure you don't have any rules that exclude cmd.exe -->
##   </ProcessCreate>
##
## References:
##   https://docs.python.org/3/library/subprocess.html#subprocess.TimeoutExpired
##   https://stackoverflow.com/questions/847850/cross-platform-way-of-getting-temp-directory-in-python
##
def trigger1():
    tempdir = tempfile.gettempdir()
    trigger = tempdir + "\\1trigger.exe"
    result = shutil.copyfile("C:\\Windows\\System32\\cmd.exe", trigger)
    time.sleep(1)
    cmd = [trigger]
    try:
        process = subprocess.run(cmd, timeout=5)
    except subprocess.TimeoutExpired:
        pass
    except:
        print("EventID 1: ERROR")
        return
    result = os.remove(trigger)
    print("EventID 1: Triggered")
    return

##
## Function Name:
##   trigger2()
##
## Purpose:
##   Triggers Sysmon Event ID 2
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 2: A process changed a file creation time
##     The change file creation time event is registered when a file creation time is explicitly modified by a process.
##     This event helps tracking the real creation time of a file.
##     Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
##     Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <FileCreateTime onmatch="include">
##     <TargetFilename condition="end with">trigger.txt</TargetFilename> <!--Look for Trigger file -->
##   </FileCreateTime>
##
## References:
##   https://technologytales.com/2014/10/29/changing-file-timestamps-using-windows-powershell/
##   https://stackoverflow.com/questions/847850/cross-platform-way-of-getting-temp-directory-in-python
##
def trigger2():
    tempdir = tempfile.gettempdir()
    f = open(tempdir + "\\2trigger.txt","w+")

    cmd1 = ["powershell.exe", "$(Get-Item " + f.name + ").creationtime"]
    cmd2 = ["powershell.exe", "$(Get-Item " + f.name + ").creationtime=$(Get-Date '1/1/1950')"]
    cmd3 = ["powershell.exe", "$(Get-Item " + f.name + ").creationtime"]
    try:
        ret = subprocess.run(cmd1, timeout=20, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ret = subprocess.run(cmd2, timeout=20, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ret = subprocess.run(cmd3, timeout=20, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        print("EventID 2: TIMEOUT")
        return
    finally:
        f.close()
        result = os.remove(f.name)

    print("EventID 2: Triggered")   
    return

##
## Function Name:
##   trigger3()
##
## Purpose:
##   Triggers Sysmon Event ID 3
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 3: Network connection
##     The network connection event logs TCP/UDP connections on the machine. It is disabled by default.
##     Each connection is linked to a process through the ProcessId and ProcessGUID fields.
##     The event also contains the source and destination host names IP addresses, port numbers and IPv6 status.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <NetworkConnect onmatch="include">
##     <Image condition="image">powershell.exe</Image> <!--Microsoft:Windows: PowerShell interface-->
##   </NetworkConnect>
##
## References:
##   https://learn-powershell.net/2011/02/11/using-powershell-to-query-web-site-information/
##
def trigger3():
    cmd = ["powershell.exe", "$wc = New-Object system.Net.WebClient; $wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'); $wp = $wc.downloadString('http://dsu.edu'); exit;"]
    try:
        ret = subprocess.run(cmd, timeout=120)
    except subprocess.TimeoutExpired:
        print("EventID 3: TIMEOUT")
        return
    print("EventID 3: Triggered")
    return

##
## Function Name:
##   trigger4()
##
## Purpose:
##   Triggers Sysmon Event ID 4
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 4: Sysmon service state changed
##     The service state change event reports the state of the Sysmon service (started or stopped).
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <!-- This event cannot be filtered. -->
##
## References:
##   https://docs.python.org/3/library/subprocess.html
##
def trigger4():
    mycwd = os.getcwd()
    cmd1 = ["powershell.exe", "Restart-Service", "sysmon"]
    try:
        ret = subprocess.run(cmd1, timeout=60, cwd=mycwd, shell=False)
    except subprocess.TimeoutExpired:
        print("EventID 4: TIMEOUT")
        return
    
    print("EventID 4: Triggered")
    return

##
## Function Name:
##   trigger5()
##
## Purpose:
##   Triggers Sysmon Event ID 5
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 5: Process terminated
##     The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId of the process.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <ProcessTerminate onmatch="include">
##     <Image condition="begin with">C:\Users</Image> <!--Process terminations by user binaries-->
## OR
##     <Image condition="end with">trigger.exe</Image> <!-- Look for Trigger -->
##   </ProcessTerminate>
##
## References:
##   https://docs.python.org/3/library/subprocess.html
##  https://stackoverflow.com/questions/847850/cross-platform-way-of-getting-temp-directory-in-python
##
def trigger5():
    tempdir = tempfile.gettempdir()
    trigger = tempdir + "\\5trigger.exe"
    result = shutil.copyfile("C:\\Windows\\System32\\calc.exe", trigger)
    time.sleep(2)
    cmd = [trigger]
    try:
        ret = subprocess.run(cmd, timeout=1)
    except subprocess.TimeoutExpired:
        pass

    result = os.remove(trigger)
    time.sleep(2)
    print("EventID 5: Triggered")
    return

##
## Function Name:
##   trigger6()
##
## Purpose:
##   Triggers Sysmon Event ID 6
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 6: Driver loaded
##     The driver loaded events provides information about a driver being loaded on the system.
##     The configured hashes are provided as well as signature information.
##     The signature is created asynchronously for performance reasons and indicates if the file was removed after loading.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <DriverLoad onmatch="exclude">
##     <!--COMMENT:	Because drivers with bugs can be used to escalate to kernel permissions, be extremely selective
##			about what you exclude from monitoring. Low event volume, little incentive to exclude.-->
##     <Signature condition="contains">microsoft</Signature> <!--Exclude signed Microsoft drivers--> 
##     <Signature condition="contains">windows</Signature> <!--Exclude signed Microsoft drivers--> 
##     <Signature condition="begin with">Intel </Signature> <!--Exclude signed Intel drivers--> 
##   </DriverLoad>
##
## References:
##   https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
##   https://docs.python.org/3/library/subprocess.html
##
def trigger6():

    mycwd = os.getcwd()
    cmd1 = [mycwd + "\\ProcessMonitor\\Procmon.exe", "/AcceptEula", "/Minimized", "/Runtime", "3"]
    try:
        ret = subprocess.run(cmd1, timeout=30, cwd=mycwd, shell=False)
    except subprocess.TimeoutExpired:
        print("EventID 6: TIMEOUT")
        return
    
    print("EventID 6: Triggered")
    return

##
## Function Name:
##   trigger7()
##
## Purpose:
##   Triggers Sysmon Event ID 7
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 7: Image loaded
##     The image loaded event logs when a module is loaded in a specific process.
##     This event is disabled by default and needs to be configured with the –l option. It indicates the process in which the module is loaded, hashes and signature information.
##     The signature is created asynchronously for performance reasons and indicates if the file was removed after loading.
##     This event should be configured carefully, as monitoring all image load events will generate a large number of events.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <ImageLoad onmatch="include">
##     <ImageLoaded condition="end with">trigger.dll</ImageLoaded> <!-- Look for Trigger --> 
##   </ImageLoad>
##
## References:
##   https://stackoverflow.com/questions/32732751/unload-dll-loaded-in-python
##   https://stackoverflow.com/questions/847850/cross-platform-way-of-getting-temp-directory-in-python
##
def trigger7():
    tempdir = tempfile.gettempdir() 
    trigger = tempdir + "\\7trigger.dll"
    result = shutil.copyfile("C:\\Windows\\System32\\user32.dll", trigger)
    time.sleep(2)
    try:
        m = ctypes.cdll.LoadLibrary(trigger)
        _ctypes.FreeLibrary(trigger)
        time.sleep(5)
    except OSError as e:
        # Ignore dll initialization errors... we just want to trigger loading
        if e.winerror == 1114:
            pass
        else:
            print("EventID 7: ERROR", e)
            return
    except:
        print("EventID 7: ERROR", sys.exc_info())
        return

    result = os.remove(trigger)
    print("EventID 7: Triggered")
    return

##
## Function Name:
##   trigger8()
##
## Purpose:
##   Triggers Sysmon Event ID 8
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 8: CreateRemoteThread
##     The CreateRemoteThread event detects when a process creates a thread in another process.
##     This technique is used by malware to inject code and hide in other processes.
##     The event indicates the source and target process.
##     It gives information on the code that will be run in the new thread: StartAddress, StartModule and StartFunction.
##     Note that StartModule and StartFunction fields are inferred, they might be empty if the starting address is outside loaded modules or known exported functions.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <CreateRemoteThread onmatch="exclude">
##     <!--COMMENT:	Monitor for processes injecting code into other processes. Often used by malware to cloak their actions.
##			Exclude mostly-safe sources and log anything else.-->
##   </CreateRemoteThread>
##
## References:
##   https://github.com/infodox/python-dll-injection/blob/master/dll_inject.py
##   https://stackoverflow.com/questions/7989922/opening-a-process-with-popen-and-getting-the-pid
##   https://www.christophertruncer.com/injecting-shellcode-into-a-remote-process-with-python/
##   https://docs.python.org/3/library/subprocess.html
##  https://stackoverflow.com/questions/847850/cross-platform-way-of-getting-temp-directory-in-python
##
def trigger8():
    tempdir = tempfile.gettempdir() 
    trigger = tempdir + "\\8trigger.exe"
    result = shutil.copyfile("C:\\Windows\\System32\\calc.exe", trigger)
    time.sleep(3)
    
    process = subprocess.Popen(trigger, shell=False)

    page_rwx_value = 0x40
    process_all = 0x1F0FFF
    memcommit = 0x00001000
    kernel32_variable = ctypes.windll.kernel32
    shellcode = "\x90\x90\x90\x90"
    process_id = process.pid
    shellcode_length = len(shellcode)
    process_handle = kernel32_variable.OpenProcess(process_all, False, process_id)
    result = memory_allocation_variable = kernel32_variable.VirtualAllocEx(process_handle, 0, shellcode_length, memcommit, page_rwx_value)
    result = kernel32_variable.WriteProcessMemory(process_handle, memory_allocation_variable, shellcode, shellcode_length, 0)
    result = kernel32_variable.CreateRemoteThread(process_handle, None, 0, memory_allocation_variable, 0, 0, 0)

    result = process.kill()
    time.sleep(4)
    result = os.remove(trigger)
    print("EventID 8: Triggered")
    return

##
## Function Name:
##   trigger9()
##
## Purpose:
##   Triggers Sysmon Event ID 9
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 9: RawAccessRead
##     The RawAccessRead event detects when a process conducts reading operations from the drive using the \\.\ denotation.
##     This technique is often used by malware for data exfiltration of files that are locked for reading, as well as to avoid file access auditing tools.
##     The event indicates the source process and target device.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <RawAccessRead onmatch="include">
##     <Image condition="end with">powershell.exe</Image>
##     <Image condition="end with">wmic.exe</Image>
##   </RawAccessRead>
##
## References:
##   https://ardamis.com/2012/08/21/getting-a-list-of-logical-and-physical-drives-from-the-command-line/
##   https://docs.python.org/3/library/subprocess.html
##
def trigger9():
    cmd = ["powershell.exe", "wmic.exe", "diskdrive", "list"] 
    try:
        result = subprocess.run(cmd, timeout=60)
    except:
        print("EventID 9: ERROR", sys.exc_info())
        return
    time.sleep(5)
    print("EventID 9: Triggered")
    return

##
## Function Name:
##   trigger10()
##
## Purpose:
##   Triggers Sysmon Event ID 10
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 10: ProcessAccess
##     The process accessed event reports when a process opens another process, an operation that’s often followed by information queries or reading and writing the address space of the target process.
##     This enables detection of hacking tools that read the memory contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash attacks.
##     Enabling it can generate significant amounts of logging if there are diagnostic utilities active that repeatedly open processes to query their state, so it generally should only be done so with filters that remove expected accesses.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <ProcessAccess onmatch="include"> <!--TEST-->
##     <SourceImage condition="end with">trigger.exe</SourceImage> <!-- Look for trigger -->
##   </ProcessAccess>
##
## References:
##   https://docs.python.org/3/library/subprocess.html
##
def trigger10():
    mycwd = os.getcwd()
    tempdir = tempfile.gettempdir() 
    trigger = tempdir + "\\10trigger.exe"
    result = shutil.copyfile("C:\\Windows\\System32\\cmd.exe", trigger)
    cmd = [trigger, "/c " + trigger + " /c echo trigger"]
    try:
        result = subprocess.run(cmd, timeout=60, cwd=mycwd, stdout=subprocess.PIPE, shell=False, check=True)
    except:
        print("EventID 10: ERROR", sys.exc_info())
        return
    result = os.remove(trigger)
    print("EventID 10: Triggered")
    return

##
## Function Name:
##   trigger11()
##
## Purpose:
##   Triggers Sysmon Event ID 11
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 11: FileCreate
##     File create operations are logged when a file is created or overwritten.
##     This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <FileCreate onmatch="include">
##     <TargetFilename condition="end with">.exe</TargetFilename> <!--Executable-->
##   </FileCreate>
##
## References:
##  https://stackoverflow.com/questions/847850/cross-platform-way-of-getting-temp-directory-in-python
##
def trigger11():
    tempdir = tempfile.gettempdir() 
    trigger = tempdir + "\\11trigger.exe"
    result = shutil.copyfile("C:\\Windows\\System32\\CMD.EXE", trigger)
    result = os.remove(trigger)
    print("EventID 11: Triggered")
    return

##
## Function Name:
##   trigger121314()
##
## Purpose:
##   Triggers Sysmon Event ID 12, 13, and 14
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 12: RegistryEvent (Object create and delete)
##     Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations, or specific malware registry modifications.
##
##   Event ID 13: RegistryEvent (Value Set)
##     This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD.
##
##   Event ID 14: RegistryEvent (Key and Value Rename)
##     Registry key and value rename operations map to this event type, recording the new name of the key or value that was renamed.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <RegistryEvent onmatch="include">
##     <TargetObject condition="contains">\CurrentVersion\Run</TargetObject> 
##   </RegistryEvent>
##
## References:
##   https://stackoverflow.com/questions/37357411/adding-an-exe-file-to-registry-on-windows-run-at-startup-via-python
##   https://stackoverflow.com/questions/2632199/how-do-i-get-the-path-of-the-current-executed-file-in-python
##   http://blogs.microsoft.co.il/pavely/2015/09/29/regrenamekey-hidden-registry-api/
##   https://www.blog.pythonlibrary.org/2010/03/20/pythons-_winreg-editing-the-windows-registry/
##
def trigger121314():
    keyVal = r'Software\CurrentVersion\Run'
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keyVal, 0, winreg.KEY_ALL_ACCESS)
    except:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, keyVal)
    winreg.SetValueEx(key, "Trigger", 0, winreg.REG_SZ, "trigger1213")   
    winreg.DeleteValue(key, "Trigger")

    keyVal = r'Software\CurrentVersion\Run\14Trigger'
    try:
        key2 = winreg.OpenKey(winreg.HKEY_CURRENT_USER, keyVal, 0, winreg.KEY_ALL_ACCESS)
    except:
        key2 = winreg.CreateKey(winreg.HKEY_CURRENT_USER, keyVal)
        
    m = ctypes.cdll.LoadLibrary("c:\\windows\\system32\\advapi32")
    ret = m.RegRenameKey(key2.handle,0,r"New14Trigger")

    winreg.DeleteKey(key, r"New14Trigger")
    winreg.CloseKey(key)
    winreg.CloseKey(key2)
    
    print("EventID 12: Triggered")
    print("EventID 13: Triggered")
    print("EventID 14: Triggered")
    return

##
## Function Name:
##   trigger15()
##
## Purpose:
##   Triggers Sysmon Event ID 15
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 15: FileCreateStreamHash
##     This event logs when a named file stream is created, and it generates events that log the hash of the contents of the file to which the stream is assigned (the unnamed stream), as well as the contents of the named stream. There are malware variants that drop their executables or configuration settings via browser downloads, and this event is aimed at capturing that based on the browser attaching a Zone.Identifier “mark of the web” stream.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <FileCreateStreamHash onmatch="include">
##     <TargetFilename condition="end with">.bat</TargetFilename> <!--Batch scripting-->
##   </FileCreateStreamHash>
##
## References:
##   http://www.powertheshell.com/ntfsstreams/
##   https://www.irongeek.com/i.php?page=security/altds
##
def trigger15():
    cmd1 = ["cmd.exe", "/c echo howdy > 15trigger.bat"]
    cmd2 = ["cmd.exe", "/c echo trigger>15trigger.bat:triggerADS.bat"]
    cmd3 = ["cmd.exe", "/c del 15trigger.bat"]
    
    try:
        ret = subprocess.run(cmd1, timeout=20)
        ret = subprocess.run(cmd2, timeout=20)
        ret = subprocess.run(cmd3, timeout=20)
    except subprocess.TimeoutExpired:
        print("EventID 15: TIMEOUT")
        return

    print("EventID 15: Triggered")
    return

##
## Function Name:
##   trigger16()
##
## Purpose:
##   Triggers Sysmon Event ID 16
##
## Input:
##   Path to Sysmon Executable
##   Path to Desired Sysmon Configuration File
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 16: Sysmon Configuration File Changed
##     Sysmon configuration file changed
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <!--Cannot be filtered.-->
##
## References:
##   https://docs.python.org/3/library/subprocess.html
##
def trigger16(sysmon_path, config_path):
  
    mycwd = os.getcwd()
    cmd1 = [sysmon_path, "-c", config_path]
    try:
        ret = subprocess.run(cmd1, timeout=30, cwd=mycwd, shell=False)
    except subprocess.TimeoutExpired:
        print("EventID 16: TIMEOUT")
        return
    
    print("EventID 16: Triggered")
    return

##
## Function Name:
##   trigger1718(), pipeserver(), pipeclient()
##
## Purpose:
##   Triggers Sysmon Event ID 17 and 18
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 17: PipeEvent (Pipe Created)
##     This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication.
##
##   Event ID 18: PipeEvent (Pipe Connected)
##     This event logs when a named pipe connection is made between a client and a server.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <PipeEvent onmatch="include"> 
##     <PipeName condition="end with">trigger</PipeName> <!-- Look for Trigger -->
##   </PipeEvent>
##
## References:
##   https://docs.python.org/3/library/subprocess.html
##   https://stackoverflow.com/questions/1430446/create-a-temporary-fifo-named-pipe-in-python
##   https://stackoverflow.com/questions/13319679/createnamedpipe-in-python
##   https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf
##   http://www.bogotobogo.com/python/Multithread/python_multithreading_creating_threads.php
##
def pipeserver():

    cmd = ["cmd.exe", "/c powershell [reflection.Assembly]::LoadWithPartialName('system.core'); $pipe = new-object System.IO.Pipes.NamedPipeServerStream('\\\\.\\pipe\\18trigger'); $pipe.WaitForConnection(); $pipe.Dispose();"]
    try:
        ret = subprocess.run(cmd, timeout=30, shell=False)
    except subprocess.TimeoutExpired:
        print("EventID 17: TIMEOUT")
        return
    print("EventID 17: Triggered")
    return

def pipeclient():

    cmd = ["cmd.exe", "/c powershell [reflection.Assembly]::LoadWithPartialName('system.core'); $pipe=new-object System.IO.Pipes.NamedPipeClientStream('\\\\.\\pipe\\18trigger'); $pipe.Connect(); $pipe.Dispose();"]
    try:
        ret = subprocess.run(cmd, timeout=30, shell=False)

    except subprocess.TimeoutExpired:
        print("EventID 18: TIMEOUT")
        return
    print("EventID 18: Triggered")
    return

def trigger1718():
    c = threading.Thread(target=pipeclient)
    c.start()
    time.sleep(5)
    s = threading.Thread(target=pipeserver)
    s.start()
    time.sleep(5)

    return

##
## Function Name:
##   trigger192021()
##
## Purpose:
##   Triggers Sysmon Event ID 19, 20, and 21
##
## Input:
##   Path to trigger.mof file 
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 19: WmiEvent (WmiEventFilter activity detected)
##     When a WMI event filter is registered, which is a method used by malware to execute, this event logs the WMI namespace, filter name and filter expression.
##
##   Event ID 20: WmiEvent (WmiEventConsumer activity detected)
##     This event logs the registration of WMI consumers, recording the consumer name, log, and destination.
##
##   Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
##      When a consumer binds to a filter, this event logs the consumer name and filter path.
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   <WmiEvent onmatch="exclude">
##     <!-- <Name condition="contains">Trigger</Name> Trigger event to verify functionality -->
##   </WmiEvent>	
##
## References:
##   https://gist.github.com/mattifestation/aff0cb8bf66c7f6ef44a
##   https://soykablog.wordpress.com/2013/04/17/removing-permanent-wmi-event-registrations-trevor-sullivans-tech-room/
##   https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/
##
def trigger192021(mof_path):

    ## CREATE WMI EVENTS
    cmd1 = ["cmd.exe", "/c", "mofcomp.exe", mof_path]
    try:
        ret = subprocess.run(cmd1, timeout=30, shell=False)
    except subprocess.TimeoutExpired:
        print("EventID 19: TIMEOUT")
        print("EventID 20: DID NOT RUN")
        print("EventID 21: DID NOT RUN")
        return

    time.sleep(5)

    ## REMOVE THE WMI EVENTS WE CREATED, TRIGGERS DELETE EVENTS

    cmd = "powershell.exe"    
    args="\"Get-WmiObject -Namespace 'root/subscription' -Class '__FilterToConsumerBinding' -Filter 'Filter=\\\"__EventFilter.Name=\\\\\\\"TriggerFilter\\\\\\\"\\\"' | Remove-WmiObject\" "
    ret = ctypes.windll.shell32.ShellExecuteW(None, u"runas", cmd, args, None, 0)
    time.sleep(5)

    print("EventID 21: Triggered")

    cmd = "powershell.exe"
    args = "\"Get-WmiObject -Namespace 'root/subscription' -Class '__EventFilter' -Filter 'Name=\\\"TriggerFilter\\\"' | Remove-WmiObject\" "
    ret = ctypes.windll.shell32.ShellExecuteW(None, u"runas", cmd, args, None, 0)
    time.sleep(5)

    print("EventID 19: Triggered")

    cmd = "powershell.exe"
    args= "\"Get-WmiObject -Namespace 'root/subscription' -Class 'CommandLineEventConsumer' -Filter 'Name=\\\"TriggerConsumer\\\"' | Remove-WmiObject\" "
    ret = ctypes.windll.shell32.ShellExecuteW(None, u"runas", cmd, args, None, 0)
    time.sleep(5)
    
    print("EventID 20: Triggered")
    return

##
## Function Name:
##   trigger255()
##
## Purpose:
##   Triggers Sysmon Event ID 255
##
## Sysmon Event Details (from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon):
##   Event ID 255: Error
##      This event is generated when an error occurred within Sysmon.
##      They can happen if the system is under heavy load and certain tasked could not be performed or a bug exists in the Sysmon service.
##      You can report any bugs on the Sysinternals forum or over Twitter (@markrussinovich).
##
## Sysmon Configuration to Match Trigger (https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml):
##   Not Implemented	
##
def trigger255():
  print("EventID 255: Not Implemented")
  return

##
## Function Name:
##
## Purpose:
##   Triggers all Sysmon events
##
## Input:
##   Modify "sysmon_path", "config_path", and "mof_path" to match your environment locations and names.
##
def main():

    # CHECK FOR ADMIN RIGHTS (your mileage may vary)
    if not has_admin():
        print("ADMIN RIGHTS REQUIRED!!!")
        return
    
    # GET DETAILS ABOUT CURRENT FILE AND DIRECTORY
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    dirname = os.path.dirname(os.path.abspath(filename))

    
    # MODIFY THESE VALUES TO MATCH YOUR ENVIRONMENT LOCATIONS AND NAMES
    sysmon_path = "C:\\progra~1\\Sysmon-v6.20\\sysmon.exe"
    config_path = dirname + os.path.sep + "sysmonconfig-modified.xml"
    mof_path = dirname + os.path.sep + "trigger.mof"
    
    print("VERIFY YOUR FILE LOCATIONS MATCH TO ENSURE TRIGGERS WORK:")
    print("Sysmon Path: ", sysmon_path)
    print("Sysmon Config File: ", config_path)
    print("Manifest File: ", mof_path)
    print("")

    # TRIGGER ALL EVENTS (numerically out of order to prevent timing issues)
    print("[ START ]")
    r = trigger9()
    r = trigger1()
    r = trigger2()
    r = trigger3()
    r = trigger4()
    r = trigger5()
    r = trigger6()
    r = trigger10()
    r = trigger11()
    r = trigger121314()
    r = trigger15()
    r = trigger16(sysmon_path, config_path)
    r = trigger1718()
    r = trigger192021(mof_path)
    r = trigger7()
    r = trigger8()
    print("[ DONE ]")
    
    return
  
if __name__== "__main__":
    main()
