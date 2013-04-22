# Wordpress Brute Protect 
#
# Author::    Peter Kepes  (https://github.com/kepes)
# Copyright:: Copyright (c) 2002 CodePlay Solutions LLC
# Web:: http://tarhelypark.hu
# Github:: https://github.com/tarhelypark/wordpress-brute-protect 
#
# The script analyse webserver log files and try to find WordPress
# bruteforce attempt. If found call specified command to block IP
# address of attacker.
# 

require 'yaml'
require 'json'

# Log one line and put timestamp into
def log (text)
  puts "#{Time.new.to_s} #{text}"
end

# First argument must be config.yaml file
if ARGV[0].nil?
  puts "I need config.yaml file!"
  exit
end

config_name=ARGV[0]
unless File.exist? config_name
  puts "Config file not found!"
  exit
end

# Load YAML xonfig
config = YAML.load_file(config_name)
config['apache_logs_pattern'] = config['apache_logs_pattern'].tr('?', '*')

# Create data dir if it isn't exists
unless Dir.exist? config['data_dir']
  Dir.mkdir config['data_dir'], 0700
end

log "-- Start log check ------------------------------------------------------"
ipdeny = Array.new

# Iterate over all log files
Dir.glob(config['apache_logs'] + '/' + config['apache_logs_pattern']) do |dir|
  # Except files with name in exclude config parameter
  exclude = false
  config['exclude_names'].each do |e|
    exclude = exclude || dir.include?(e)
  end
  next if exclude
  
  # Initialize log_data to store suspicious IP addresses and other usefull info
  log_data = nil
  if File.exist? "#{config['data_dir']}/" + File.basename(dir) + ".dat"
    File.open("#{config['data_dir']}/" + File.basename(dir) + ".dat","r") do |fdata|
      log_data = fdata.gets
      log_data = JSON.parse(log_data) unless log_data.nil?
    end
  end
  
  # Store actual log size an modify time
  log_size = File.size(dir)
  log_mtime = File.mtime(dir).to_s
  
  # Check if log file changed since our last check
  if !log_data.nil? && log_mtime == log_data['mtime']
    # Log if file not changed
    #log "Log file not changed: #{dir}"
  else
    # If file changed open it
    File.open(dir,'r') do |file|
      log_first_line = file.gets
      
      # If log_data is nil this is our first read so we need to initialize iplist for attackers
      if log_data.nil?
        iplist = Hash.new
      else
        iplist = log_data['iplist']
      end
      
      # if this is our first read and apache_logs_start_last config param is true we have to skip 
      # entire log file first
      if log_data.nil? && config["apache_logs_start_last"]
        log "First read, past entries ignored: #{dir}"
      else 
        # if this is not our first read skip to last known position (last file size)
        if !log_data.nil? && log_first_line == log_data['first_line']
          file.seek log_data['size']
        else 
          # if this is our first read or first line of the log file changed 
          # since our last read (file rotated and restarted)
          # we have to start at the begining
          file.seek 0
        end  
        
        # Count line numbers
        lineNr = 0
        
        # Read log lines
        while line = file.gets
          # Try to match regexp to log line
          fields = line.scan /^(.+) (.+) (.+) \[(.*)\] "(.*)" (.+) (.+) "(.*)" "(.*)"$/
          fields = fields[0]
          lineNr = lineNr + 1
          log "#{lineNr} lines processed" if lineNr%10000 == 0
          
          # If regexp not matched log an error
          if fields.nil?
            log "Can't process line: " + line
            
          # If line is a wp-login.php POST and client Ip not in deny list this is an attack
          elsif fields[4].include?("POST /wp-login.php") && !ipdeny.include?(fields[0])
            # If we already found other attack from same IP
            if iplist.has_key?(fields[0]) 
              # count this attack
              iplist[fields[0]] = iplist[fields[0]] + 1
              
              # if there is more than 5 try in iplist we have to deny the IP
              if iplist[fields[0]] == 5
                # put IP to ipdeny 
                ipdeny << fields[0]
                # delete from iplist
                iplist.delete fields[0]
                log "attacker found: " + fields[0]
              end
            else
              # First try we have to initialize iplist with IP address
              iplist[fields[0]] = 1
            end
          else 
            # If current line isn't wp-login.php or Ip already denied delete IP from IP list
            iplist.delete fields[0] if iplist.has_key?(fields[0])
          end
        end
        log lineNr.to_s + " lines checked in #{dir}"
      end
      
      # Save iplist and log info for next run into JSON data file
      File.open("#{config['data_dir']}/" + File.basename(dir) + ".dat","w") do |fdata|
        log_data = Hash.new
        log_data[:size] = log_size
        log_data[:mtime] = log_mtime
        log_data[:iplist] = iplist
        log_data[:first_line] = log_first_line
        
        fdata.puts JSON.generate(log_data)
      end
    end
  end
end

# Deny all IP address what we found
ipdeny.each do |ip|
  cmd = config['deny_cmd'] + ' ' + ip
  log "deny ip: #{ip}"
  #log "command: #{cmd}"
  `#{cmd}` 
  #log "command output: " + $?.to_s
end

log "-- Log check Finished ---------------------------------------------------"
