require 'yaml'
require 'json'

if ARGV[0].nil?
  puts "I need config.yaml file!"
  exit
end

config_name=ARGV[0]
unless File.exist? config_name
  puts "Config file not found!"
  exit
end

config = YAML.load_file(config_name)
config['apache_logs_pattern'] = config['apache_logs_pattern'].tr('?', '*')

unless Dir.exist? config['data_dir']
  Dir.mkdir config['data_dir'], 0700
end
  
Dir.glob(config['apache_logs'] + '/' + config['apache_logs_pattern']) do |dir|
  exclude = false
  config['exclude_names'].each do |e|
    exclude = exclude || dir.include?(e)
  end
  next if exclude
  
  log_data = nil
  if File.exist? "#{config['data_dir']}/" + File.basename(dir) + ".dat"
    File.open("#{config['data_dir']}/" + File.basename(dir) + ".dat","r") do |fdata|
      log_data = fdata.gets
      log_data = JSON.parse(log_data) unless log_data.nil?
    end
  end
  
  log_size = File.size(dir)
  log_mtime = File.mtime(dir).to_s
  
  if !log_data.nil? && log_mtime == log_data['mtime']
    #puts "Log file not changed: " + dir
  else
    File.open(dir,'r') do |file|
      log_first_line = file.gets
      
      if log_data.nil?
        iplist = Hash.new
      else
        iplist = log_data['iplist']
      end
      
      if log_data.nil? && config["apache_logs_start_last"]
        puts "First read, past entries ignored: #{dir}"
      else 
        if !log_data.nil? && log_first_line == log_data['first_line']
          file.seek log_data['size']
        else 
          file.seek 0
        end  
    
        ipdeny = Array.new
        lineNr = 0
        while line = file.gets
          fields = line.scan /^(.+) (.+) (.+) \[(.*)\] "(.*)" (.+) (.+) "(.*)" "(.*)"$/
          fields = fields[0]
          lineNr = lineNr + 1
          puts lineNr if lineNr%10000 == 0
          if fields.nil?
            puts "Can't process line: " + line
          elsif fields[4].include?("POST /wp-login.php") && !ipdeny.include?(fields[0])
            if iplist.has_key?(fields[0]) 
              iplist[fields[0]] = iplist[fields[0]] + 1
          
              if iplist[fields[0]] == 5
                ipdeny << fields[0]
                iplist.delete fields[0]
                puts "attacker found: " + fields[0]
              end
            else
              iplist[fields[0]] = 1
            end
          else 
            if iplist.has_key?(fields[0])
              iplist.delete fields[0]
            end
          end
        end
        puts lineNr.to_s + " lines checked in #{dir}"
        ipdeny.each do |ip|
          puts "deny " + ip
          cmd = config['deny_cmd'] + ' ' + ip
          puts "command: #{cmd}"
          `#{cmd}` 
          puts "command output: " + $?.to_s
        end
      end
      
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