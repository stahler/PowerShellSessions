# Answer 1
$regex = '^[a-z]{4}\d{2}$|^[a-z]{3}\d{2,3}$|^[a-z]{2}\d{2,4}$'
(Get-ADGroup -filter {name -eq '[IT ALL IT]'} -Properties members).members |
    Get-ADUser -Properties mail,displayname | Where-Object samaccountname -Match $regex |
    Select-Object samaccountname, mail, displayname

# Answer 2
Get-ADGroup -Filter {GroupCategory -eq 'Distribution'} -Properties members |
    Where-Object {($_.Members | Measure-Object).Count -le 10} | Measure-Object

# Answer 2.1
# What if I wanted the count
Get-ADGroup -Filter {GroupCategory -eq 'Distribution'} -Properties members |
    Where-Object {($_.Members | Measure-Object).Count -le 10} |
    Select-Object Name, @{Name = 'Cnt'; Expression = {($_.Members | Measure-Object).Count}}

# Answer 3
$city = 'Powell','Grove City','Gahanna','Dublin'
Get-ADUser -Filter * -Properties City | Where-Object City -in $city | Measure-Object

# Answer 4
$regex = '^[a-z]{4}\d{2}$|^[a-z]{3}\d{2,3}$|^[a-z]{2}\d{2,4}$'
Search-ADAccount -AccountDisabled –UsersOnly |
    Where-Object DistinguishedName -NotLike '*OU=Disabled,DC=OSUMC,DC=EDU' |
    Where-Object samaccountname -Match $regex |
Select-Object samaccountname, DistinguishedName

# Answer 4.1 Enabled in Disabled OU
Get-ADUser -Filter {enabled -eq $true} | Where-Object DistinguishedName -Like '*OU=Disabled,DC=OSUMC,DC=EDU' |
Measure-Object

