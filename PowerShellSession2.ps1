<#####  PowerShell Session 2: Introduction continued #####
Agenda

1. Aliases
    * How to find
      Get-Alias -Definition Get-ChildItem
    * Parameter aliases
      Undocumented
      (Get-Command Get-EventLog).parameters.computername.aliases
2. Show-Command (Good for learning)
3. Old school commands
   Undocumented
    * https://collaborate.osumc.edu/it/staff/TSS/ServerTeam/ScriptingBlog/Lists/Posts/Post.aspx?ID=121
4. Get-PSProvider
    * Get-PSDrive
    * Set-Location env: ;(Get-ChildItem Path ).Value -split ";"
    * Certs
    * AD
5. Pipeline
    * Export-CSV/XML
    Dir > c:\temp\dir.list
    Dir | Out-File c:\temp\dir.list
    Out-GridView (Poormans Excel)

    ConvertTo-HTML
    Get-Process | Stop-Process
6. Compare-Object
7. Measure-Object

Exercises:
Get a list of all enabled inbound firewall rules
What is the difference between -Filter, -Include, -Exclude parameters of Get-ChildItem

#>