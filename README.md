# hosts2unbound
extends the unbound blocklist with simple host file(s), unbound config file(s) or single host(s)

hosts2unbound is used as a helper script together with a working unbound configuration. It requires a separate unbound include file which stores only blocked sites, respectively. This so called output file will be overwritten during runtime. One or more input files can be also added with simple hosts file syntax or with the complex unbound syntax. The input file(s) will be interpreted and merged together with the content of the output file.

Also one or more single hosts with domain ending can be added as well.

When all the files and hosts are processed, the script can reload the unbound configuration with the C<unbound-control reload> command, if needed. After the reload all modifications are applied.

The script requires almost as much memory as the size of the files, since the hostnames with domain name will be stored in memory, before they are flused with the appropriate unbound deny syntax to the output file.
