wordpress-brute-protect
=======================

Brute force protection tool for hosting administrators. Designed mainly for cPanel hosting envirnoment but should works on any webserver.

Scan all specified webserver log files and try to find IP addresses which brutes wordpress installations. If found call deny_cmd to disallow access. Deny command can be iptables or csf

Usage
-----------------------
```console
ruby analyse.rb ./config.yaml
``` 

Best in cron job:
```console
#/etc/cron.d/wordpress-block
SHELL=/bin/sh
*/2 * * * * root        /usr/local/bin/ruby /root/analyse.rb /home/root/config.yaml >> /var/log/wordpress-block.log
```
config.yaml format
-----------------------
```ruby
data_dir: /var/lib/wordpress-brute
apache_logs: /usr/local/apache/domlogs/
apache_logs_pattern: ?/?
deny_cmd: /usr/sbin/csf --deny
apache_logs_start_last: true
whitelist: 111.111.111.111, 222.222.222.222
exclude_names:
  - bytes_log
  - ftp_log
```

## Configuration parameters
* data_dir: where to store data files
* apache_logs: where to find apache logs
* apache_logs_pattern: pattern for finding logs in format for glob
* deny_cmd: command from deny an IP address
* apache_logs_start_last: true if old logs NOT processed and start from the end of all log file. False for process all logs from the begining. Only affect the first run of the script. Usefull on working systems with large log files. If false first run can take long time!   
* whitelist: script will not deny this IP addresses
* exclude_names: exclude log files with names specified here

## TODO
* Logging
* Check if process already running
