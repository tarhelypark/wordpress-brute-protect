wordpress-brute-protect
=======================

Brute force protection tool for hosting administrators. Designed mainly for cPanel hosting enirnoment but should works on any webserver.

Scan all specified webserver log files and try to find IP addresses which brutes wordpress installations. If found call deny_cmd to disallow access. Deny command can be iptables or csf

Usage
-----------------------
```console
ruby analyse.rb ./config.yaml
``` 

config.yaml format
-----------------------
```ruby
data_dir: /var/lib/wordpress-brute
apache_logs: /usr/local/apache/domlogs/
apache_logs_pattern: ?/?
deny_cmd: csf --deny
apache_logs_start_last: true
exclude_names:
  - bytes_log
  - ftp_log
```

## Configuration parameters
* data_dir: where to store data files
* apache_logs: where to find apache logs
* apache_logs_pattern: pattern for finding logs in format for glob
* deny_cmd: command from deny an IP address
* apache_logs_start_last: true if old logs not processed and start from the end of all log file. False for process all logs from the begining. Only affect the first run of the script.  

## TODO
* Logging
