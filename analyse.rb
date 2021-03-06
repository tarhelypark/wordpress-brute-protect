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
require 'daemons'

# Log one line and put timestamp into
def log (text)
  @log_file.puts "#{Time.new.to_s} #{text}"
  @log_file.flush
end

# Parameters without the daemons gem's parameters
my_array = ARGV[ARGV.index('--') + 1, ARGV.size]

# First argument must be config.yaml file
if my_array[0].nil?
  puts "I need config.yaml file!"
  exit
end

config_name=my_array[0]
unless File.exist? config_name
  puts "Config file not found!"
  exit
end

# Load YAML xonfig
config = YAML.load_file(config_name)
whitelist = config['whitelist'].split(',')
whitelist.collect! { |ip| ip.strip }

# Create data dir if it isn't exists
unless Dir.exist? config['data_dir']
  Dir.mkdir config['data_dir'], 0700
end

Daemons.run_proc('analyze.rb', {dir_mode: :normal, dir: config['data_dir']}) do
  loop do
    @log_file = File.open("#{config['log']}","a")

    log "-- Start log check ------------------------------------------------------"
    ipdeny = Array.new

    top_access = Array.new
    top_size = Array.new

    # Iterate over all log files
    Dir.glob(config['apache_logs'] + '/' + config['apache_logs_pattern']) do |dir|
      # Next round if it is not a file
      next unless File.file?(dir)
      # Except files with name in exclude config parameter
      exclude = false
      config['exclude_names'].each do |e|
        exclude = exclude || dir.include?(e)
      end
      next if exclude

      # Initialize log_data to store suspicious IP addresses and other usefull info
      log_data = nil
      data_file_path = "#{config['data_dir']}/#{File.absolute_path(dir)}"
      data_file_name = "#{data_file_path}/#{File.basename(dir)}.dat"
      if File.exist? data_file_name
        File.open(data_file_name,"r") do |fdata|
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
          log "Processing #{dir}"
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
            # Count transfer size
            transSize = 0

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
              else
                # Add transfer size if size is an integer
                if fields[6].to_i.to_s == fields[6]
                  transSize = transSize + fields[6].to_i
                elsif fields[6] != '-'
                  log "Wrong transfer size: " + line
                end

                # If line is a wp-login.php POST and client Ip not in deny list this is an attack
                if fields[4].include?("POST /wp-login.php") && !ipdeny.include?(fields[0])
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

                # If browser is DirBuster deny it immediately
                elsif fields[8].include?("DirBuster") && !ipdeny.include?(fields[0])
                  ipdeny << fields[0]
                  log "DirBuster found: " + fields[0]

                else
                  # If current line isn't wp-login.php or Ip already denied delete IP from IP list
                  iplist.delete fields[0] if iplist.has_key?(fields[0])
                end
              end
            end
            log lineNr.to_s + " lines checked in #{dir}"

            # Generate top access log list
            top_access << { nr:lineNr, file:dir }
            top_access = top_access.sort_by { |top| top[:nr] }.reverse.take(config["max_top_access"])

            # Generate top size log list
            top_size << { size:transSize, file:dir }
            top_size = top_size.sort_by { |top| top[:size] }.reverse.take(config["max_top_access"])
          end

          # create data file folder without fileutils gem
          tmp_path = config['data_dir']
          File.absolute_path(dir).split('/').each do |d|
            tmp_path = tmp_path + d
            Dir.mkdir(tmp_path) unless Dir.exist?(tmp_path)
            tmp_path += '/'
          end

          # Save iplist and log info for next run into JSON data file
          File.open(data_file_name,"w") do |fdata|
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
      if whitelist.include? ip
        log "Attacker on whitelist: #{ip}"
      else
        cmd = config['deny_cmd'] + ' ' + ip
        log "Deny ip: #{ip}"
        #log "command: #{cmd}"
        `#{cmd}`
        #log "command output: " + $?.to_s
      end
    end

    File.open("#{config['top_access_log']}","a") do |ftop|
      ftop.puts "#{Time.new.to_s} -- Top access logs ---------------------------------------------------"
      top_access.each do |top|
        ftop.puts "#{Time.new.to_s} #{top[:nr]} #{top[:file]}"
      end
    end

    File.open("#{config['top_size_log']}","a") do |ftop|
      ftop.puts "#{Time.new.to_s} -- Top size logs ---------------------------------------------------"
      top_size.each do |top|
        ftop.puts "#{Time.new.to_s} #{top[:size] / 1024} #{top[:file]}"
      end
    end

    log "-- Log check Finished ---------------------------------------------------"

    @log_file.close

    sleep(config['sleep_time'])
  end
end
