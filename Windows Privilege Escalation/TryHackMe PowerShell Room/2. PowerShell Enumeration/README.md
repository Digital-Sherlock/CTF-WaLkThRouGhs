# Enumeration

1. How many users are there on the machine?

**_Get-LocalUser_** or **_Net User_** commands.

_Both commands show users present in the system._

2. Which local user does this SID(S-1-5-21-1394777289-3961777894-1791813945-501) belong to?

**_Get-LocalUser -SID 'S-1-5-21-1394777289-3961777894-1791813945-501'_**

_The command will show the user holding the above SID value (RID = 501, Guest)._

3. How many users have their password required values set to False?


```powershell
Get-LocalUser | Get-Memmber # checking the Get-LocalUser properties
Get-LocalUser -Name Username | Select-Object -Property PasswordRequired
```

_The command above will outline users with PasswordRequired property set rather to True or False._

4. How many local groups exist?

**Get-LocalGroup | Measure-Object -Line**

_The first object shows the local groups while the second one counts lines in the previous object._

5. How many ports are listed as listening?

**Get-NetTcpConnection | Sort-Object -Property State -eq 'Listen' | Measure-Object Line**

_The first object is an analog of the netstat command showing open ports on the system. The second and third obkects do the filtering._

6. What is the remote address of the local port listening on port 445?

**Get-HotFix | Measure-Object -Line**

_The first cmdlet shows the updates installed on the system as well as Source, Description, HotFixID, InstalledBy, and InstalledOn properties._

7. Find the contents of a backup file.

```powershell
Get-ChildItem -Path C:\*.bak* -Recurse -Force 2>$null 3>$null
Get-Content ...
```

[Redirection tutorial](https://ss64.com/ps/syntax-redirection.html) for redirecting different outputs to files, $null, etc.

_**-Force** shows hidden files while **2,3>$null** redirects error and warning messages to nowhere._

8. Search for all files containing API_KEY

```powershell
Get-ChildItem -Path C:\*.txt* -Recurse -Force 2>$null 3>$null | Select-String -Pattern 'API_KEY'
```

9. What is the path of the scheduled task called new-sched-task?

```powershell
(Get-Command Get-ScheduledTaskInfo).Parameter
Get-ScheduledTaskInfo -TaskName 'new-sched-task'
```

_(Get-Command Get-ScheduledTaskInfo).Parameter outputs parameters for the Get-ScheduledTaskInfo command._

10. Who is the owner of the C:\

```powershell
Get-Acl -Path C:\
```
_Outputs the security descriptor of the directory including the owner._
