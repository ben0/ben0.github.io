---
layout: single
title: "Exploring Windows API with PowerShell & C#"
---

Recently, I subscribed to Ruben Boonen (b33f) Patreon becuase I thought this would be a great oppurtunity to learn some new stuff! Every now and then b33f released a live session where he chatted through a particular topic, one of these was how you can use the Windows API in PowerShell.

I always thought this was a rather complex topic, and veered away from programming but it's actually really interesting and quite fun.

Anyway moving on there are a few ways of achieving this but I'm going to stick with inline C#.

Using inline C# is pretty simple but can be troublesome and I failed a lot. It uses the Add-Type cmdlet in PowerShell which essentially allows you to add a C# class to PowerShell.

Microsoft has a great document for this - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.1

Here is an example of calling a Windows API method using this approach:

```
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public static class WindowsAPI {

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync
    (
        IntPtr hWnd,
        int nCmdShow
    );
};
"@

[IntPtr]$handle = (Get-Process -Pid $PID).MainWindowHandle
[WindowsAPI]::ShowWindowAsync($handle,0)
```

In the example above, you can see we're invoking Add-Type cmdlet with the here string containing the inline C#, we're using the class name WindowsAPI, and using the ShowWindowAsync function, I use PInvoke for the signatures great - https://www.pinvoke.net/default.aspx/user32.showwindowasync, but Googling the function name + "MSDN" or "DLLImport" will help.

Within the function you may have to work change the type from C++ to C#, I've have included some type conversion here: https://raw.githubusercontent.com/ben0/PS-WinAPI/master/Types.md

After we've declared the signature, we get a handle to our current processes main window, then we can call the class and method with the variables $handle, and 0 to hide the current window! Great for hiding a PowerShell window!

Using this technique we can do much more, for example using the CreateProcessWithToken function.

```
function CreateProcessWithToken {

	<#
    .SYNOPSIS
    Achieve CreateProcessWithTokenW
	
	.DESCRIPTION

    .PARAMETER processname
    
    .PARAMETER spawn

	.EXAMPLE
	
	.INPUTS
	System.String
	
	.OUTPUTS
	None

    .NOTES
    The following five token flags are required, otherwise the error is access denied:
        TOKEN_ASSIGN_PRIMARY
        TOKEN_DUPLICATE
        TOKEN_QUERY
        TOKEN_ADJUST_DEFAULT
        TOKEN_ADJUST_SESSIONID

    
	.LINK
	
	#>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$processname,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$spawn
    )
	Begin {
        Add-Type -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Principal;
    
        public enum ProcessAccess
		{
			PROCESS_ALL_ACCESS = (PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE),
			PROCESS_CREATE_PROCESS = 0x0080,
			PROCESS_CREATE_THREAD = 0x0002,
			PROCESS_DUP_HANDLE = 0x0040,
			PROCESS_QUERY_INFORMATION = 0x0400,
			PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
			PROCESS_SET_INFORMATION = 0x0200,
			PROCESS_SET_QUOTA = 0x0100,
			PROCESS_SUSPEND_RESUME = 0x0800,
			PROCESS_TERMINATE = 0x0001,
			PROCESS_VM_OPERATION = 0x0008,
			PROCESS_VM_READ = 0x0010,
			PROCESS_VM_WRITE = 0x0020,
			SYNCHRONIZE = 0x00100000
        };
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION 
        {
            public Int32 cb;
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        };

        public enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        };

        public enum CreationFlags
        {
            CREATE_SUSPENDED = 0x00000004,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000
        };

        public enum TOKEN_TYPE 
        {
            TokenPrimary = 1,
            TokenImpersonation
        };

        public enum SECURITY_IMPERSONATION_LEVEL 
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        };

        public static class WindowsAPICreateProcess
        {
            public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
            public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
            public const UInt32 TOKEN_DUPLICATE = 0x0002;
            public const UInt32 TOKEN_IMPERSONATE = 0x0004;
            public const UInt32 TOKEN_QUERY = 0x0008;
            public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
            public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
            public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
            public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
            public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
            public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
            public const UInt32 TOKEN_CREATEPROCESSWITHTOKEN = (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
            public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);

			[DllImport("kernel32.dll", SetLastError=true)]
			public static extern IntPtr OpenProcess
			(
				UInt32 processAccess,
				bool bInheritHandle,
				int processId
            );

            [DllImport("advapi32.dll", SetLastError=true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool OpenProcessToken
            (
                IntPtr ProcessHandle, 
                UInt32 DesiredAccess,
                out IntPtr TokenHandle
            );
            
            [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
            public extern static bool DuplicateTokenEx
            (
                IntPtr hExistingToken,
                uint dwDesiredAccess,
                ref SECURITY_ATTRIBUTES lpTokenAttributes,
                SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                TOKEN_TYPE TokenType,
                out IntPtr phNewToken
            );

            [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessWithTokenW
            (
                IntPtr hToken, 
                LogonFlags dwLogonFlags,
                string lpApplicationName, 
                string lpCommandLine, 
                CreationFlags dwCreationFlags, 
                IntPtr lpEnvironment, 
                string lpCurrentDirectory, 
                [In] ref STARTUPINFO lpStartupInfo, 
                out PROCESS_INFORMATION lpProcessInformation
            );
            
        }
"@
	}
	Process {
        Write-Host -ForegroundColor Black -BackgroundColor Yellow "CreateProcessWithTokenW PoC:"

		# Retrieve the Process ID of $processname
		#
		$ProcessID = (Get-Process -Name ${processname} -ErrorAction SilentlyContinue).Id
		if(!$ProcessID)
		{
			Write-Host -Foregroundcolor Red "[!] Could not find ${processname} running..."
			Break
		} elseif ($ProcessID -is [array]) {
			$ProcessID = $ProcessID[0]
		}
		Write-Host -Foregroundcolor White -NoNewLine "[+] Process ID of ${processname}: "
		Write-Host -Foregroundcolor Green $ProcessID
		
        
		# Open the remote process
		# PROCESS_ALL_ACCESS = 0x1F0FFF
		# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
		#
		[IntPtr]$handleProcess = 0
		$handleProcess = [WindowsAPICreateProcess]::OpenProcess([ProcessAccess]::PROCESS_ALL_ACCESS, $false, $ProcessID); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to process ${processname}/$ProcessID is: "
        if($handleProcess -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
		    Write-Host -Foregroundcolor Green $handleProcess
        }


		# Open the process token
		# Access: TOKEN_DUPLICATE
        # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        #
        # Declare our Int for handle to the token
        [IntPtr]$handleToken = [IntPtr]::Zero
		$returnValue = [WindowsAPICreateProcess]::OpenProcessToken($handleProcess, [WindowsAPICreateProcess]::TOKEN_DUPLICATE, [ref]$handleToken); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to token ${processname}/$ProcessID is: "
        if($handleToken -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
            Write-Host -Foregroundcolor Green $handleToken
        }


        # Define and populate the Startupinfo struct, including the struct size
        $SECURITY_ATTRIBUTES = New-Object -Typename SECURITY_ATTRIBUTES
        
        # Duplicate the process token
        # Access: 
        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
        #
        # Delcare our Int for handle to the token
        [IntPtr]$duplicateToken = [IntPtr]::Zero
        $DuplicateTokenResult = [WindowsAPICreateProcess]::DuplicateTokenEx($handleToken, [WindowsAPICreateProcess]::TOKEN_ALL_ACCESS, [ref]$SECURITY_ATTRIBUTES, [SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, [TOKEN_TYPE]::TokenImpersonation, [ref]$duplicateToken); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to duplicate token is: "
        if($duplicateToken -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
        } else {
            Write-Host -Foregroundcolor Green $duplicateToken
        }

        # Define and populate the Startupinfo struct, including the struct size
        $STARTUPINFO = New-Object -Typename STARTUPINFO
        $STARTUPINFO.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($STARTUPINFO)

        # Define and populate the Startupinfo struct, including the struct size
        $PROCESS_INFORMATION = New-Object -Typename PROCESS_INFORMATION
        $PROCESS_INFORMATION.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($PROCESS_INFORMATION)

        # Call the function
        $APICallResult = [WindowsAPICreateProcess]::CreateProcessWithTokenW($duplicateToken, [LogonFlags]::LOGON_WITH_PROFILE, $spawn, $spawn, [CreationFlags]::CREATE_NEW_CONSOLE, 0, "C:\\", [ref]$STARTUPINFO, [ref]$PROCESS_INFORMATION); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Calling function CreateProcessWithTokenW: "

        # GetLastError courtesy of Exploit Monday
        # http://www.exploit-monday.com/2016/01/properly-retrieving-win32-api-error.html
        if($LastError -eq 1314)
        {
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Red "$LastError ERROR_PRIVILEGE_NOT_HELD"
        } elseif ($LastError -eq 0) 
        {
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Red "$LastError"
        } elseif ($LastError -ne 0) {
            Write-Host -Foregroundcolor White -NoNewline "[!] Success with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
        }
    }

	End {
	}
}
```

With this inline C# it's possible to get the token of another process, duplicate it and then create a new process with the privileges of that token. Neat!