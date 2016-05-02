The script allows you to keep 1 js file per each of your security groups.
That file will list all needed CIDRs to whitelist (inbound rules), and any comments, if you want to know which IP is what :)
Such files are located in subfolder "security groups", and current "index.js" reads all files in folder, when an update operation is run ("node updateSecGroupRules.js")

A short how-to, for those who want to use this script:

1. Use file "TEMPLATE_SG.js" as template for list of IPs for particular security group,
rename this file as you want. Place into folder "security-groups", and populate all needed values (sg ID, name, IPs, place needed comments)

2. Then to update all SGs that you placed files for them into "security-groups" folder, run "node updateSecGroupRules.js" and watch for output.

3. To list current rules in all your chosen SGs, run "node updateSecGroupRules.js" any time. It will go over each SG in folder and list its current state.

P.S. By "chosen SGs" I mean all those files you placed into folder "security groups". Each file is 1 SG with all needed IPs listed.

P.S.2. Sorry if I sound like explaining to dumb :D  it sometimes helps to read the same thing 2 times in readme... better more documentation than less :)

Thank you!