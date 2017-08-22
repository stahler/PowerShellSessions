########################################################################################
# Active Directory session
# Assuming that everyone has RSAT installed so they can use the Active Directory Module
# Test this by running: Get-ADUser kast04
########################################################################################
Break # Do this to keep from running all commands below at once

########################################################################################
# Slight review from previous session
Get-Command -Module ActiveDirectory | Measure-Object
Get-Command -Module ActiveDirectory -Verb Get
Get-Command -Module ActiveDirectory -Noun ADUser

########################################################################################
# Start off with some simple Gets (Sets will come later)
Get-ADUser kast04

Get-ADComputer 'SEC-SCRIPT-VT01'

Get-Content ./servers.txt | Get-ADComputer

Import-Csv -Path ./itsecurity.csv | Select-Object -ExpandProperty samAccountName | Get-ADUser

# or (I typically do it this way)
(Import-Csv ./itsecurity.csv).samAccountName | Get-ADUser

Get-ADGroup ITSecurity
'Network Team','Office for Scholarship' | Get-ADGroup

# Lets get more info!
# PowerShell by default returns a small subset of attributes
Get-ADUser kast04

# What is available to me?
Get-ADUser kast04  -Properties *

# Add a few specific attributes
Get-ADUser kast04 -Properties LastBadPasswordAttempt, LastLogonDate, PasswordLastSet

# Look at specifically what I want
Get-ADUser kast04 -Properties LastBadPasswordAttempt, LastLogonDate, PasswordLastSet |
Select-Object Name, LastBadPasswordAttempt, LastLogonDate, PasswordLastSet

########################################################################################
# Filtering

# single filter
Get-ADUser -Filter {samaccountname -like 'stah0*'} | Select-Object Name, samaccountname

# multiple filter
Get-ADUser -Filter {surname -like 'stah*' -AND samaccountname -like 'stah0*'} |
Select-Object Name, samaccountname

# multiple filter with an additional attribute
Get-ADUser -Filter {Department -eq 'Data Security (92274)'} -Properties DisplayName |
Select-Object SamAccountName, DisplayName

# LDAPFilter (Old school, LDIFDE, LDP, CSVDE)
$LDAP = "(&(Description=*test account*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
Get-ADUser -LDAPFilter $ldap | Select-Object Name, samaccountname, enabled

# Sometimes you can't use the filter parameter (or being lazy).
Get-ADUser -Filter * -SearchBase 'OU=Disabled,DC=OSUMC,DC=EDU' |
Where-Object enabled -eq $true | Measure-Object

# Better example (Getting "human users")
$regex = '^[a-z]{4}\d{2}$|^[a-z]{3}\d{2,3}$|^[a-z]{2}\d{2,4}$'
Get-ADUser -Filter * |
Where-Object samaccountname -Match $regex |
Select-Object samaccountname, name

# Another example finding all non-human users but this time, just looking in a particular OU
Get-ADUser -Filter * -SearchBase 'OU=Disabled,DC=OSUMC,DC=EDU' |
Where-Object SamAccountName -notmatch $regex |
Select-Object SamAccountName, Name

########################################################################################
# Sorting, Grouping and Exporting
Get-ADComputer -filter * -SearchBase 'OU=Citrix,DC=OSUMC,DC=EDU' |
Sort-Object Name | Select-Object Name

Get-ADComputer -filter * -SearchBase 'OU=Citrix,DC=OSUMC,DC=EDU' -properties OperatingSystem |
Sort-Object Name | Select-Object Name, OperatingSystem | Export-Csv -Path C:\TEMP\Citrix.csv -NoTypeInformation

# Sort all computer objects in AD by OS count
Get-ADComputer -Filter * -Properties OperatingSystem |
Group-Object -Property OperatingSystem -NoElement |
Sort-Object -Property Count -Descending

########################################################################################
# Search-ADAccount examples
Search-ADAccount -LockedOut -UsersOnly
Search-ADAccount -AccountExpired | Get-ADUser
Search-ADAccount -PasswordExpired -UsersOnly -Credential 'osumc\adm-wes'

########################################################################################
# Other common examples
# Get Groups that are sam for two users
$user1 = (Get-ADPrincipalGroupMembership gard26 | Sort-Object samAccountName).SamAccountName
$user2 = (Get-ADPrincipalGroupMembership stah06 | Sort-Object samAccountName).SamAccountName
Compare-Object $user1 $user2 -ExcludeDifferent -IncludeEqual

# Get Groups that in one but not the other
$user1 = (Get-ADPrincipalGroupMembership gard26 | Sort-Object samAccountName).SamAccountName
$user2 = (Get-ADPrincipalGroupMembership stah06 | Sort-Object samAccountName).SamAccountName
Compare-Object $user1 $user2 | Where-Object SideIndicator -eq "<=" |
Out-GridView -Title "Groups that Brett has, that Wes doesnt"

# Get empty groups
Get-ADGroup -Filter {GroupCategory -eq 'Distribution'} -Properties members |
Where-Object {($_.Members | Measure-Object).count -eq 0} | Measure-Object

# or another way
Get-ADGroup -Filter {GroupCategory -eq 'Distribution'} -Properties members, description, managedby |
Where-Object {-not $_.Members} | Select-Object Name, samAccountName, Description, managedby |
Out-GridView -Title "These be empty groups"

# filtering with a text file of IP addresses
Get-Content C:\TEMP\ip.txt | ForEach-Object {
        Get-ADComputer -Filter {ipv4address -eq $_} -Properties Operatingsystem |
        Select-Object Name, Operatingsystem
}

# filtering via email address
Get-Content -Path C:\TEMP\mail.txt | ForEach-Object {Get-ADuser -Filter {mail -eq $psitem}}

# Tricky one.....
# Getting last bad password date (Will explain during session)
(Get-ADDomainController -Filter *).Name |
ForEach-Object {
    Get-ADUser stah06 -Server $PSItem -Properties LastBadPasswordAttempt |
    Select-Object LastBadPasswordAttempt
}

#################################################################################################
# Fancy manager report
# also an example of a computed column, calculated property, custom field, so many names....
# also shows how to grab a particular value from an array
Get-ADUser -Filter * -Properties DepartmentNumber, Manager, Department, DisplayName |
Where-Object {$PSItem.DepartmentNumber[0] -eq '92274' -AND $PSItem.Enabled -eq $true} |
Select-Object DisplayName, samaccountname, department, Manager,
@{Name = 'CC';Expression = {$PSItem.DepartmentNumber[0]}},
@{N='ManagerID';E={(Get-ADUser $PSItem.manager).samaccountname}} |
Out-GridView -Title "92274 Employees"

###################################################################################################
# Poor mans histogram
Get-ADComputer -Filter { operatingSystem -like '*Window*Server*' } -Properties OperatingSystem -OutVariable s |
Group-Object OperatingSystem -NoElement | Sort-Object -Property Count -Descending |
Select-Object @{ N = ”OpertaingSystem”; E = { $_.Name } }, Count,
       @{ N = ”Count%”; E = { "{0:%##}" -f $($_.Count/$s.Count) } },
       @{ N = ”Histogram”; E = { “▄” * [int]($($_.Count/$s.Count) * 100) } } |
       Out-GridView

###################################################################################################
# Looking for mortal accounts that have are in the local adminstrators group
# Regex to find "human" non-elevated accounts
$regex = '^[a-z]{4}\d{2}$|^[a-z]{3}\d{2,3}$|^[a-z]{2}\d{2,4}$'

# Group we wish to interogate
$group = 'lsa-ii-nilcv-vp02'

((Get-ADGroup $group -Properties members).members | Get-ADGroup -Properties members).members |
    Get-ADUser | Where-Object samaccountname -Match $regex | Select-Object samaccountname

# Bonus tip
# Get-Clipboard example

# Test time:
# Jamie wants the DisplayName and email address for all "humans" in the '[IT ALL IT]' group
# How many distribution lists have 10 or fewer members?
# How many people in Active Directory are from 'Powell','Grove City','Gahanna','Dublin'?

# Questions, comments, concerns?