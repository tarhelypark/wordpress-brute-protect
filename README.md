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
data_dir: /var/lib/wordpress-brute
apache_logs: /usr/local/apache/domlogs/
apache_logs_pattern: ?/?
deny_cmd: echo
apache_logs_start_last: true
```