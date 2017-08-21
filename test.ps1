#$regex = '^[a-z]{4}\d{2}$|^[a-z]{3}\d{2,3}$|^[a-z]{2}\d{2,4}$'
#$group = 'lsa-ii-nilcv-vp02'
#$group = 'svr-script-vp01'

#((Get-ADGroup $group -Properties members).members | Get-ADGroup -Properties members).members |
#    Get-ADUser | Where-Object samaccountname -Match $regex | Select-Object samaccountname

Get-ADUser fara23