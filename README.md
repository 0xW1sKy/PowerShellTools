# PowerShellTools

### DnsCmdlets.psm1

These Cmdlets use Dns.getHostEntry method to collect info about a target specified by a string (ip or resolvable dns name).
Results are filtered and returned based on the command.

#### Easy setup:
``` 
mkdir c:\Windows\System32\WindowsPowerShell\v1.0\Modules\DnsCmdlets
copy c:\Users\<your-username>\Downloads\DnsCmdlets.psm1 c:\Windows\System32\WindowsPowerShell\v1.0\Modules\DnsCmdlets\DnsCmdlets.psm1 
```
