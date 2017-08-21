<#####  PowerShell Session 1: Introduction  #####  
Agenda

1. Prerequisites
    * Windows 10 (Windows 7 will suffice)
    * PowerShell version 3+ (version 5 preferred)
      Type $PSVersionTable to verify
2. Console vs Integrated Scripting Environment (ISE)
3. ISE
    * Script Editor Pane
    * Commands Explorer
    * Console Pane
    * Tab Completion
      Tab / Shift-Tab
      Dir c:\
      Get-Service -
      Get-Service -I
      Get-Service (ISE)
4. Verb-Noun
5. Get-Command
    -Verb
    -Noun
    -Module
6. Help
    * Update-Help (gots to be an administrator)
    * Save-Help (disconnected boxes)
        New-Item -Path C:\TEMP -Name HELP -ItemType Directory
        Save-Help -DestinationPath C:\TEMP\HELP -Force
    * Get-Help
    * Help
    * Man
    * About
    * -ShowWindow
    * -Online
    * ParameterSets (Get-EventLog)
    * Optional / Mandatory
    * Positional
    * Collection parameters 
        Introduce Get-Content
        Get-WmiObject -ComputerName (Get-Content C:\TEMP\servers.txt) -Class win32_computersystem -Credential (Get-Credential osumc\adm-wes)
    * -Example
7. Exercises (the kind I know)
    Find cmdlets that deal with converting data 
    Find cmdlets that deal with Processes
    Find cmdlets that have the verb Stop/Start
    Is there a help topic to assist with Arrays?
    Is there a way to limit the number of events returned from the event log?                        

8. Sign of things to come....
   Any idea what this is doing?

Get-Command | 
Group-Object -Property Verb -NoElement | 
Where-Object -Property Count -gt 100 |
Sort-Object -Property Count -Descending | 
Out-GridView -Title "Piping example"

or

GCM | Group Verb -no | ? Count -gt 100 | Sort Count | OGV

#>