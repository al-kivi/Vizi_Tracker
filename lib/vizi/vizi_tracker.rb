# This gem module provides a set of classes to support the parsing of web log files and
# the creation of Visit records from the individual parsed web log records
#
# The LogFormat and LogParser classes were derived in part from an Apache logger application
# developed by Jan Wikholm. These two classes were extended to support both Apache and IIS
# web logs. The details from the web logs are assembled to compose Visit objects and Visit 
# history detail.
#
# Author::    Al Kivi <al.kivi@vizitrax.com>
# License::   MIT

module Vizi
# This class handles the parsing of each line in the log file
  class LogFormat
    attr_reader :name, :format, :format_symbols, :format_regex

    DIRECTIVES = {
        # format string char => [:symbol to use, /regex to use when matching against log/]
        'h' => [:ip, /\d+\.\d+\.\d+\.\d+/], 	# apache and IIS: called c-ip in IIS
        'p' => [:sip, /\d+\.\d+\.\d+\.\d+/],	# IIS:
        'g' => [:auth, /\S*/],								# apache:
        'u' => [:username, /\S*/],						# apache and IIS: called cs-username in IIS
        't' => [:dtstring, /\[.*?\]/],				# apache: one field with date and time
        'd' => [:datestring, /\d+\-\d+\-\d+/],	# IIS:
        'e' => [:timestring, /\d+\:\d+\:\d+/],	# IIS:       
        'r' => [:request, /.*?/],							# apache: includes both csmethod and csuristem
        'm' => [:csmethod, /\w*?/],						# IIS:
        'w' => [:csuristem, /\S*/],						# IIS:             
        's' => [:status, /\d+/],							# apache and IIS: is called sc_status in IIS
        'b' => [:bytecount, /-|\d+/],					# apache and IIS: is called cs_bytes in IIS
        'v' => [:domain, /.*?/],							# apache and IIS: is c-computername in IIS
        'i' => [:header_lines, /.*?/],				# apache: transforms to useragent or referer or cookies
        'a' => [:useragent, /\S*/],						# IIS: 
        'j' => [:referer, /\S*/],							# IIS: 
        'k' => [:cscookie, /\d+/],						# IIS:                    
        'q' => [:csuriquery, /.*/],						# IIS:
        'y' => [:csbytes, /d+/],							# IIS:
        'o' => [:sport, /\d+/],								# IIS:
        'x' => [:scsubstatus, /\d+/],					# IIS:
        'z' => [:cshost, /\d+/],							# IIS:       
        'l' => [:win32status, /\d+/],					# IIS: 
        'n' => [:timetaken, /\d+/],						# IIS:
        'c' => [:comment, /^#/],							# IIS: comment line identifier      
        'f' => [:fields, /^#Fields:/]					# IIS: field line identifier 
    }

# This method initializes the LogFormat object with fieldnames and log formats
    def initialize(name, format)
      @name, @format = name, format
      parse_format(format)
    end

# The symbols are used to map the log to the env variables
# The regex is used when checking what format the log is and to extract data
    def parse_format(format)
      format_directive = /%(.*?)(\{.*?\})?([#{[DIRECTIVES.keys.join('|')]}])([\s\\"]*)/
      log_format_symbols = []
      format_regex = ""
      format.scan(format_directive) do |condition, subdirective, directive_char, ignored|
        log_format, match_regex = process_directive(directive_char, subdirective, condition)
        ignored.gsub!(/\s/, '\\s') unless ignored.nil?
        log_format_symbols << log_format
        format_regex << "(#{match_regex})#{ignored}"
      end
      @format_symbols = log_format_symbols
      @format_regex = /^#{format_regex}/
    end

    def process_directive(directive_char, subdirective, condition)
      directive = DIRECTIVES[directive_char]
      case directive_char
        when 'i'
          log_format = subdirective[1...-1].downcase.tr('-', '_').to_sym
          [log_format, directive[1].source]
        else
          [directive[0], directive[1].source]
      end
    end
  end

# This class handles the parsing of each line in the log file
  class LogParser
    require 'time'

    LOG_FORMATS = {
        :common => '%h %g %u %t \"%r\" %>s %b',
        :common_with_virtual => '%v %h %g %u %t \"%r\" %>s %b',
        :combined => '%h %g %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"',
        :combined_with_virtual => '%v %h %g %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"',
        :combined_with_cookies => '%h %g %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" \"%{Cookies}i\"',
        :w3c_c => '%c', # format is comment ... still looking
        :w3c_f => '%f' # format is IIS fields ... ready to parse
    }

    FIELDNAMES = {
        'c-ip' => 'h',
        's-ip' => 'p',
        'cs-username' => 'u',
        'sc-status' => 's',
        'cs-bytes' => 'y',
        'sc-bytes' => 'b',
        'date' => 'd',
        'time' => 'e',
        'cs-method' => 'm',
        'cs-uri-stem' => 'w',
        'cs-uri-query' => 'q',
        'cs(Referer)' => 'j', 		# internal shortened to referer
        'cs(User-Agent)' => 'a', 	# internal shortened to useragent
        'cs(Cookie)' => 'k', 			# internal shortened to cscookie        
        's-port' => 'o',
        'cs-host' => 'z',       
        'sc-substatus' => 'x',
        'sc-win32-status' => 'l',
        'time-taken' => 'n',
        's-computername' => 'v'
    }

    attr_reader :known_formats

    #@@log = ActiveRecord::Base.logger

# This method initialises LogParser object and loads the configurable logger control items
    def initialize(drop_ips, spider_ips, spider_names, include_urls, exclude_urls, url_stem, accept_only_url_stem, 
        hostname, drop_refers_by_hostname, usualagents, use_local_time)
      @drops = drop_ips
      @sips = spider_ips
      @snames = spider_names
      @include_urls = include_urls
      @exclude_urls = exclude_urls
      @url_stem = url_stem
      @accept_only_url_stem = accept_only_url_stem
      @hostname = hostname
      @drop_refers_by_hostname = drop_refers_by_hostname
      @usualagents = usualagents
      @use_local_time = use_local_time
      @log_format = []
      initialize_known_formats
      @parselog = Logger.new('./log/parse.log', shift_age = 'weekly')
      @parselog.level = Logger::WARN
    end

# Processes the format string into symbols and test regex and saves using LogFormat class
    def initialize_known_formats
      @known_formats = {}
      LOG_FORMATS.each do |name, format|
        @known_formats[name] = Vizi::LogFormat.new(name, format)
      end
    end

# Checks which standard the log file (well one line) is
# Automatically checks for most complex (longest) regex first ...
    def check_format(line)
      @known_formats.sort_by { |key, log_format| log_format.format_regex.source.size }.reverse.each { |key, log_format|
        return key if line.match(log_format.format_regex)
      }
      return :unknown
    end

# Builds the format from the IIS fielnames 
    def build_format(line)
      fields = line.split(' ')
      i = 1
      @format = ""
      while i < fields.length
        @format << "%"+FIELDNAMES[fields[i]]+" "
        i = i + 1
      end
      return @format
    end

# Match a partial string in field against an external field array
    def match_partial (field, fldarray)
      hit = nil
      i = 0
      while i < fldarray.length
				hit = field.index(fldarray[i])
        break if hit
        i = i + 1
      end
      return hit
    end
 
 # Find an assigned number from matching string against an external field array
    def find_assigned_number (field, fldarray)
      pageid = 0
      i = 0
      while i < fldarray.length
        hit = fldarray[i].index(field)
        if hit
          z = fldarray[i].split(',')
          pageid = z[1].to_i
          break
        end
        i = i + 1
      end
      return pageid
    end

# apache files ... regex the file to determine logformat name
# IIS files ... parse the fields string to determine the file contents
# :p_linetype   ... line is a (C)ontrol line, (F)ield line or a good (V)isitor line
# :p_pageflag   ... (Y)es is a valid page or (N)ot
# :p_vistortype ... (H)uman, (S)pider, (D)ropped or (-) Not relevant
    def parse_line(line, logformat)
      if logformat != nil
        log_format = logformat # get log_format string
        @format_name = "temp"
        data = line.split(' ')
      else
        @format_name = check_format(line) # look for matching formats, check each time
        log_format = @known_formats[@format_name] # found a matched format
        raise ArgumentError if log_format.nil? or line !~ log_format.format_regex
        data = line.downcase.scan(log_format.format_regex).flatten
      end
      parsed_data = {}
      log_format.format_symbols.size.times do |i|
        parsed_data[log_format.format_symbols[i]] = data[i] # load data for each format_symbol
      end
      
      parsed_data[:p_logformatname] = @format_name.to_s
      parsed_data[:p_logformat] = logformat
      parsed_data[:p_visitortype] = "H" # set default visitor type (H)uman
      parsed_data[:p_linetype] = "V" # linetype is (V)isitors
      parsed_data[:p_linetype] = "C" if parsed_data[:ip].nil? # reset if a comment line     
      if @format_name.to_s == "w3c_f" # IIS file name ... generic
        @format = build_format(line) # parse fields to get log_format
        temp_format = Vizi::LogFormat.new(:temp, @format) # create temp format
        parsed_data[:p_logformat] = temp_format # shuttle the log_format object
        parsed_data[:p_logformatname] = "iis" # change the name to iis
        parsed_data[:p_linetype] = "F" # linetype to (F)ield list
        parsed_data[:p_visitortype] = "-" # visitor type not relevant
      elsif @format_name.to_s == "w3c_c" # found IIS file in comments section
        parsed_data[:p_linetype] = "C" # linetype is (C)omment
        parsed_data[:p_visitortype] = "-"
      elsif  parsed_data[:p_linetype] == "C"
        @parselog.warn line
        @parselog.warn "Found comment lines embedded in the log file ... resetting to nil"
        parsed_data[:p_logformat] = nil
      else # parsing the field names

        if parsed_data[:datestring]
          dt = Time.parse(parsed_data[:datestring]+" "+parsed_data[:timestring])
          parsed_data[:datetime] = Time.gm(dt.year, dt.month, dt.day, dt.hour, dt.min, dt.sec)
          parsed_data[:datetime] = parsed_data[:datetime].getlocal if @use_local_time
        end        

        if parsed_data[:dtstring]
          parsed_data[:dtstring] = parsed_data[:dtstring][1...-1]
          parsed_data[:dtstring] = parsed_data[:dtstring].sub(":", " ")        
          dt = Time.parse(parsed_data[:dtstring])
          parsed_data[:datetime] = Time.gm(dt.year, dt.month, dt.day, dt.hour, dt.min, dt.sec)
          parsed_data[:datetime] = parsed_data[:datetime].getlocal if @use_local_time
        end

        if parsed_data[:request]
#          splitrequest = parsed_data[:request].gsub("/", " ").split
					splitrequest = parsed_data[:request].split(' ')
          parsed_data[:csuristem] = splitrequest[1]
        end

#     Now determine visitortype based on logger yml rules ...
        parsed_data[:p_pageflag] = "N"	        
				if @accept_only_url_stem  # indicates that url_stem must always appear at start of csuristem			
          parsed_data[:p_pageflag] = "Y" if parsed_data[:csuristem].downcase.index(@url_stem) == 0
        else
					if parsed_data[:csuristem].downcase == @url_stem
						parsed_data[:p_pageflag] = "Y" 
					else
						if @include_urls
							parsed_data[:p_pageflag] = "Y" if match_partial(parsed_data[:csuristem].downcase, @include_urls)
						end
						if @exclude_urls
							parsed_data[:p_pageflag] = "N" if match_partial(parsed_data[:csuristem].downcase, @exclude_urls)
						end
					end
				end
				
				parsed_data[:p_visitortype] = "D" if parsed_data[:status] == "404"			
        parsed_data[:p_visitortype] = "D" if @drops and @drops.index(parsed_data[:ip])
        parsed_data[:p_visitortype] = "S" if @sips and @sips.index(parsed_data[:ip])
        if parsed_data[:useragent] and @snames and match_partial(parsed_data[:useragent].downcase, @snames)
          parsed_data[:p_visitortype] = "S"
        end
        parsed_data[:p_visitortype] = "S" if parsed_data[:useragent] == "-"      
        parsed_data[:p_usualagent] = "Y" 
        parsed_data[:p_usualagent] = "N" if parsed_data[:p_visitortype] != "S" and not match_partial(parsed_data[:useragent].downcase, @usualagents)
        
				parsed_data[:p_returnhit] = "N"
				parsed_data[:p_returnhit] = "Y" if parsed_data[:status] == "304"

        if parsed_data[:referer]
          y = (/(search\?\S*?[pq])=(\S*?)(&)/).match(parsed_data[:referer])
          parsed_data[:p_searchphrase] = y[2] if y != nil
          if @drop_refers_by_hostname
            parsed_data[:p_visitortype] = "D" if parsed_data[:referer].index(@hostname) != nil
          end
        end
        
				parsed_data[:p_pdfstem] = nil
				parsed_data[:p_pdfstem] = parsed_data[:csuristem].downcase if parsed_data[:csuristem].downcase.index("/pdfs/") == 0
      end
      parsed_data
    end
  end

# This class creates and stores information related to each visit
# Visits are determined on the basis of the IP Address hits during a timed interval
#
  class Visit  
    attr_accessor :ip, :start_dt, :end_dt, :expire_dt, :duration, :hits, :pgcount, :robots, :vtype, 
			:returnhit, :searchphrase, :orgname, :city, :country, :region, :grouphash, :group, :groupcount, :pdfstem, :pdflist

# This method initializes the Visit object. Loads object with parsed data from first captured line
    def initialize(ip, log_dt, csuristem, csuriquery, timetaken, p_visitortype, p_pageflag, p_returnhit, p_pdfstem, visit_timeout)
      @ip = ip
      @start_dt = log_dt
      @expire_dt = @start_dt + visit_timeout
      @end_dt = @start_dt
      @duration = 0
      @hits = 0
      @pgcount = 0
      @pgcount = 1 if p_pageflag == "Y"  
      @vtype = p_visitortype
      @vtype = "S" if csuristem == "/robots.txt"
      @returnhit = p_returnhit
      @orgname = ""
      @city = ""
      @country = ""
      @region = ""
      @grouphash = Hash.new
      @group = ""
      @groupcount = 0
      @orgmatch = ""
      @searchphrase = ""
      @pdfstem = p_pdfstem
      @pdflist = Array.new 
      @pdflist << @pdfstem if not @pdfstem.nil?
      @rank = calculate_rank(@pgcount, @duration, @vtype, @pdflist.length)       
    end

# This method calculates the rank
    def calculate_rank(pgcount, duration, visitortype, pdfhits)
			if pgcount < 4
				rank = pgcount
			elsif pgcount > 10
				rank = 5
			else
				rank = 4
			end
			rank = 2 if duration < 21
			rank = 1 if duration < 11
			rank = 0 if duration < 11 and pgcount > 40
			rank = 0 if pgcount > duration/5
      rank = 0 if duration == 0
      rank = 0 if visitortype == "D"
      rank = rank + 1 if pdfhits > 0
      rank = 5 if rank > 5
      rank = -rank if visitortype == "S"
      return rank   
    end

# This method updates the Visit object with new parsed data
    def update(end_dt, p_visitortype, p_pageflag, p_returnhit, p_pdfstem)
      @end_dt = end_dt
      @duration = (@end_dt - @start_dt).to_i
      @hits = @hits + 1
      @pgcount = @pgcount + 1 if p_pageflag == "Y"        
      @vtype = p_visitortype if @vtype == "H"
      @returnhit = p_returnhit if @returnhit == "N"
      @pdfstem = p_pdfstem
			@pdflist << @pdfstem if @pdfstem and @pdflist.index(@pdfstem).nil?
      @rank = calculate_rank(@pgcount, @duration, @vtype, @pdflist.length)           
    end
    
# This method updates the Visit object with results of the whois lookup    
    def add_details(orgname, city, country, region)
			@orgname = orgname
			@city = city
			@country = country
			@region = region
    end
    
    def getip
      @ip
    end

# Get rank from object    
    def getrank
      @rank
    end

# Add count to group     
    def increment_group(group)
			@grouphash[group] = @grouphash[group].to_i + 1
    end

# Classify the visit based on various factors    
    def classify_visit
			@group = "none"
			@groupcount = 0
			if @grouphash.length > 0
				z = @grouphash.invert.sort
				zlast = z[z.length-1]
				@group = zlast[1]
				@groupcount = z.length				
			end
			case @group
				when "news", "company", "resources"
					@persona = "Analyst"
				when "home", "contacts"
					@persona = "Tirekicker"	
				when "products", "solutions"
					@persona = "Suspect"
				when "careers"
					@persona = "Jobhunter"			
				when "evolve"
					@persona = "Prospect"																
				when "partners"
					@persona = "Barney"
				when "customers"
					@persona = "Poacher"					
				else
					@persona = "None"
			end
			@persona = "Bouncer" if @rank < 3
			@persona = "Prospect" if @persona == "Suspect" and ((@rank == 4 and @returnhit == "Y") or @rank == 5) 
    end
    
# This method looks to match the orgname against the orgs file  
		def matchorg(orgs)
			@orgmatch = ""
			orgs.each {|group, names|
				names.each { |n|
					if @orgname.index(n)
						@orgmatch = group
						break
					end	
				}
			}
		end

# Print short output with key fields from the object    
    def sendoutput
      iplong = @ip+"      "
      p ">"+iplong[0..14]+" "+@start_dt.to_s[0..18]+" "+@vtype+" Pgs> "+@pgcount.to_s+" Dur> "+@duration.to_s+" Rank> "+@rank.to_s
    end
 
# Print long output with key fields from the object    
    def printoutput
      iplong = @ip+"      "
      p ">"+iplong[0..14]+" "+@start_dt.to_s[0..18]+" "+@vtype+" Pgs> "+@pgcount.to_s+" Dur> "+@duration.to_s+" Rank> "+@rank.to_s+" Org> "+@orgname+" City> "+@city+" Country> "+@country+" Region> "+@region
    end
 
    #def createcsvheader(fileout)
			#fileout.puts("ipaddress, date, time, vtype, pgcount, duration, rank, returnhit, orgname, city, country, region")
    #end    
 
    #def createcsvoutput(fileout)
			#iplong = @ip+"      "
			#fileout.puts(iplong[0..14]+","+@start_dt.to_s[0..10]+","+@start_dt.to_s[11..18]+","+@vtype+","+@pgcount.to_s+","+@duration.to_s+","+@rank.to_s+","+@returnhit+","+@orgname+","+@city+","+@country+","+@region)
    #end 
 
 # Store output to Google docs spreadsheet    
    def gdocsoutput (ws, row_count)
			r = row_count+2
			ws[r,1] = @ip
			ws[r,2] = @start_dt.strftime("%m/%d/%Y")
			ws[r,3] = @start_dt.strftime("%I:%M%p")
			ws[r,4] = @pgcount
			ws[r,5] = @duration
			ws[r,6] = (@pdflist.length)				
			ws[r,7] = @rank
			ws[r,8] = @orgname
			ws[r,9] = @city
			ws[r,10] = @country
			ws[r,11] = @region		
			ws[r,12] = @returnhit
			ws[r,13] = @persona					
			ws[r,14] = @group
			ws[r,15] = @groupcount
			ws[r,16] = @orgmatch
			ws.save()	    
    end
 
 # Save output to database file       
    def saveoutput
			@vzvisit = Vzvisit.new
			@vzvisit[:ipaddr] = @ip
			@vzvisit[:vdatetime] = @start_dt
			@vzvisit[:vtype] = @vtype
			@vzvisit[:pgcount] = @pgcount
			@vzvisit[:duration] = @duration
			@vzvisit[:rank] = @rank
			@vzvisit[:orgname] = @orgname
			@vzvisit[:city] = @city
			@vzvisit[:country] = @country
			@vzvisit[:region] = @region		
			@vzvisit[:returnhit] = @returnhit		
			@vzvisit[:grp] = @group
			@vzvisit[:groupcount] = @groupcount
			@vzvisit[:persona] = @persona
			@vzvisit[:orgmatch] = @orgmatch
			@vzvisit[:pdfhits] = @pdflist.length					
			@vzvisit.save			
    end      
    
  end

# This class creates and manages a list to keep track of the visits that are in process (cached)
# Once a visit reaches the time interval, an output transaction is generated and the visit is removed from the list
#
  class VisitList
    def initialize
      @visits = Array.new
    end

    def append(visit)
      @visits.push(visit)
      self
    end

    def delete(visit)
      @visits.delete(visit)
    end

    def find_all
      @visits
    end

    def find_by_ip(ip)
      @visits.find { |visit| ip == visit.ip }
    end

    def find_expired(test_dt)
      @visits.find { |visit| visit.expire_dt < test_dt }
    end
  end

end
