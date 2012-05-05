# This is a sample application that uses the Vizitracker gem classes
# 
# This application will open a web log file (with either an IIS or Apache format).
# Each record will be parser, and Visit records will be created. When the visit
# timeout duration has been reached, an output record will be generated.
#
# Author::    Al Kivi <al.kivi@vizitrax.com>

require 'rubygems'   # needed for ruby 1.8.7
# require '...\vizi_tracker\lib\vizi\vizi_tracker'
require 'vizi_tracker'

require 'yaml'
require 'logger'

config = YAML.load_file("config/logger.yml")

@@download_page_number = config["download_page_number"]
@@visit_timeout = config["visit_timeout"]

# Initialize the log parser
parser = Vizi::LogParser.new(config["drop_ips"], config["spider_ips"], 
	config["spider_names"], config["include_urls"], config["exclude_urls"], 
	config["url_stem"], config["accept_only_url_stem"],config["hostname"], 
	config["drop_refers_by_hostname"], config["usual_agents"], 
	config["use_local_time"])  
 
syslog = Logger.new('./log/system.log',shift_age = 'weekly')
case config["log_level"]
when "info"
  syslog.level = Logger::INFO
when "warn"
  syslog.level = Logger::WARN  
when "error"
  syslog.level = Logger::ERROR  
when "fatal"
  syslog.level = Logger::FATAL   
else
  syslog.level = Logger::DEBUG 
end
syslog.info "starting ... >>> "+Time.now.to_s

# Open log file for reading
File.open('./data/exlog.log', 'r') do |file|
  vlist = Vizi::VisitList.new
  rec_count = 0
  hit_count = 0
  max_rec_count = 99999
  max_rec_count = config["max_rec_count"] if config["max_rec_count"]
  visit_count = 0
  page_count = 0
  human_count = 0
  drop_count = 0
  spider_count = 0
  start_time = Time.now
  logformat = nil
  # Begin to parse each record
  while(line = file.gets)
#  p line
    parsed_data = parser.parse_line(line, logformat)
    logformat = parsed_data[:p_logformat]
    rec_count = rec_count + 1 
    next if parsed_data[:p_linetype] != "V"    
    hit_count = hit_count + 1
    page_count = page_count + 1 if parsed_data[:p_pageflag]
    @visit=vlist.find_by_ip(parsed_data[:ip])
	if @visit.nil?
		vlist.append(Vizi::Visit.new(parsed_data[:ip],parsed_data[:datetime],parsed_data[:csuristem],parsed_data[:csuriquery], parsed_data[:timetaken],
			parsed_data[:p_visitortype],parsed_data[:p_pageflag],parsed_data[:p_returnhit],parsed_data[:p_pdfstem],config["visit_timeout"]))
      @visit=vlist.find_by_ip(parsed_data[:ip])     
	  visit_count = visit_count + 1 
	else
	  @visit.update(parsed_data[:datetime],parsed_data[:p_visitortype],parsed_data[:p_pageflag],parsed_data[:p_returnhit],parsed_data[:p_pdfstem])
    end
    @visits = vlist.find_expired(@visit.start_dt)
    if @visits 
      @visits.sendoutput
      vlist.delete(@visits) 
      human_count = human_count + 1 if @visits.vtype == "H" 
      drop_count = drop_count + 1 if @visits.vtype == "D"
      spider_count = spider_count + 1 if @visits.vtype == "S"                   
    end
    break if rec_count == max_rec_count
  end
  @visits = vlist.find_all
  @visits.each {|v|
    v.sendoutput
    human_count = human_count + 1 if v.vtype == "H"
    drop_count = drop_count + 1 if v.vtype == "D"
    spider_count = spider_count + 1 if v.vtype == "S"      
  }  
  if config["summary_flag"]
    syslog.info "Record count is "+rec_count.to_s
    syslog.info "Hit count is "+hit_count.to_s 
    syslog.info "Page count is "+page_count.to_s      
    syslog.info "Total visit count is "+visit_count.to_s  
    syslog.info "Human visit count is "+human_count.to_s
    syslog.info "Drop visit count is "+drop_count.to_s
    syslog.info "Spider visit count is "+spider_count.to_s            
    syslog.info "Batch processing time "+(Time.now-start_time).to_s
  end
  syslog.info "ending ... >>> "+Time.now.to_s
end

