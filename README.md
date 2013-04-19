wordpress-brute-protect
=======================

Brute force protection tool for hosting administrators. Designed mainly for cPanel hosting enirnoment but should works on any webserver.

Usage
-----------------------
```console
ruby analize.rb ./analize-config.yaml
``` 

config.yaml format
-----------------------
```ruby
data_dir: /Users/kepes/Work/loganalizer/dat
apache_logs: /Users/kepes/Work/loganalizer/testlog
apache_logs_pattern: ?/?
deny_cmd: echo
apache_logs_start_last: true
```