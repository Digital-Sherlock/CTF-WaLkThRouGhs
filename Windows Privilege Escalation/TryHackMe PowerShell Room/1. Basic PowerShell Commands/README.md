# Brief PowerShell Guide

## Getting Help with Commands

List of all Verbs: [link](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7)

1. **_Get-Help -Name Command_** - prints the command info and use cases

**_-Examples_** keyword will depict a variety of the command use cases

>Example: _Get-Help -Name Get-Process -Example_ (Get-Help Get-Process is also correct)

2. **_Get-Command Verb**-* / *-**Noun_** - prints the commands list matching the pattern

>Example: Get-Command Start-*

3. **Command | _Get-Member_** - prints commands methods and properties

>Example: _Get-Command | Get-Member -MemberType Method_

4. **_Select-Object_** - creates a new object from the specified cmdlet and its properties

>Example: _Get-ChildItem C:\Users | Select-Object -Property Mode, Name_

```txt
Mode  Name
----  ----
d-r-- Guest
d---- Shared
d---- vadimpolovnikov
```
>Get-ChildItem C:\Users | Select-Object -Last <int> (-First, -Unique, -Index)

5. **_Command | Where-Object -Property [PropertyName] -operator [Value]_** - prints an object that match a specified value

>Example: _Get-Process | Where-Object -Property ProcessName -eq Terminal_

```txt
NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
      0     0.00     154.93       9.85    5032   1 Terminal
```

>Alternative: Get-Process | Where-Object {$_.ProcessName -eq 'Terminal'}

**$_** is an iterator operator.

List of Where-Object [operators](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-6).

6. **_Command | Sort-Object_** - sorts the input object by properties (default Name)

>Example: _Get-Process | Sort-Object Id -Descending | Select-Object -Last 5_

```txt
 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
      0     0.00      11.34       0.12    5250   1 mdworker_shared
      0     0.00      53.84       0.25    5208 …08 com.apple.WebKi
      0     0.00       0.00       0.00    5207 …07 
      0     0.00     131.25       0.82    5174 …74 com.apple.WebKi
      0     0.00     198.04       3.01    5173 …73 com.apple.WebKi
```

## TryHackMe Challenges

---

1. What is the location of the file "interesting-file.txt"

**Get-ChildItem C:\ -Filter 'interesting-file.txt' -Recurse**

2. Specify the contents of this file

**Get-Content -Path 'C:\Program Files\interesting-file.txt'**

3. How many cmdlets are installed on the system(only cmdlets, not functions and aliases)?

**Get-Command | Where-Object -Property CommandType -eq 'Cmdlet' | Measure-Object -Line**

4. Get the MD5 hash of interesting-file.txt

**Get-FileHash 'C:\Program Files\interesting-file.txt' -Algorithm MD5**

5. 

```powershell
Get-ChildItem C:\ -Name 'b64.txt' -Recurse
$ENCODED = Get-Content ./b64.txt
$DECODED = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ENCODED))
Write-Output $DECODED
```
