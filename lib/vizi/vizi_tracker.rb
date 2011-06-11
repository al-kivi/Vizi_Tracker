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
        'g' => [:auth, /\S*/],					# apache:
        'u' => [:username, /\S*/],				# apache and IIS: called cs-username in IIS
        't' => [:dtstring, /\[.*?\]/], 			# apache: one field with date and time
        'd' => [:datestring, /\d+\-\d+\-\d+/],	# IIS:
        'e' => [:timestring, /\d+\:\d+\:\d+/],	# IIS:       
        'r' => [:request, /.*?/], 				# apache: includes both csmethod and csuristem
        'm' => [:csmethod, /\w*?/],				# IIS:
        'w' => [:csuristem, /\S*/],				# IIS:             
        's' => [:status, /\d+/], 				# apache and IIS: is called sc_status in IIS
        'b' => [:bytecount, /-|\d+/], 			# apache and IIS: is called cs_bytes in IIS
        'v' => [:domain, /.*?/], 				# apache and IIS: is c-computername in IIS
        'i' => [:header_lines, /.*?/], 			# apache: transforms to useragent or referer or cookies
        'a' => [:useragent, /\S*/], 			# IIS: 
        'j' => [:referer, /\S*/],				# IIS: 
        'k' => [:cscookie, /\d+/],				# IIS:                    
        'q' => [:csuriquery, /.*/],				# IIS:
        'y' => [:csbytes, /d+/],				# IIS:
        'o' => [:sport, /\d+/],					# IIS:
        'x' => [:scsubstatus, /\d+/],			# IIS:
        'z' => [:cshost, /\d+/],				# IIS:       
        'l' => [:win32status, /\d+/],			# IIS: 
        'n' => [:timetaken, /\d+/],				# IIS:
        'c' => [:comment, /^#/],				# IIS: comment line identifier      
        'f' => [:fields, /^#Fields:/]			# IIS: field line identifier 
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
        'cs(Cookie)' => 'k', 		# internal shortened to cscookie        
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
    def initialize(drop_ips, spider_ips, spider_names, page_urls, hide_urls, homepage, accept_only_homepage, 
        hostname, drop_refers_by_hostname, use_local_time, assigned_numbers, match_page_numbers)
      @drops = drop_ips
      @sips = spider_ips
      @snames = spider_names
      @page_urls = page_urls
      @hide_urls = hide_urls
      @homepage = homepage
      @accept_only_homepage = accept_only_homepage
      @hostname = hostname
      @drop_refers_by_hostname = drop_refers_by_hostname
      @use_local_time = use_local_time
      @assigned_numbers = assigned_numbers
      @match_page_numbers = match_page_numbers
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

#     Now classify visitortype based on logger yml rules ...

        parsed_data[:p_pageflag] = false
        if @accept_only_homepage
        #p @homepage
        #p parsed_data[:csuristem]
          parsed_data[:p_pageflag] = true if parsed_data[:csuristem].downcase.index(@homepage) == 0
        else
          parsed_data[:p_pageflag] = true if match_partial(parsed_data[:csuristem], @page_urls)
        end
        parsed_data[:p_pageflag] = false if @hide_urls and match_partial(parsed_data[:csuristem], @hide_urls)

        parsed_data[:p_visitortype] = "D" if @drops and @drops.index(parsed_data[:ip])
        parsed_data[:p_visitortype] = "S" if @sips and@sips.index(parsed_data[:ip])

        if parsed_data[:useragent] and @snames and match_partial(parsed_data[:useragent], @snames)
          parsed_data[:p_visitortype] = "S"
        end

        if parsed_data[:referer]
          y = (/(search\?\S*?[pq])=(\S*?)(&)/).match(parsed_data[:referer])
          parsed_data[:p_searchphrase] = y[2] if y != nil
          if @drop_refers_by_hostname
            parsed_data[:p_visitortype] = "D" if parsed_data[:referer].index(@hostname) != nil
          end
        end
        
        if @match_page_numbers and parsed_data[:p_pageflag]
          parsed_data[:p_pageid] = find_assigned_number(parsed_data[:csuristem], @assigned_numbers)
#          p ">>" + parsed_data[:p_pageid].to_s if parsed_data[:p_pageid]
        end
        
      end
      parsed_data
    end
  end

# This class creates and stores information related to each visit
# Visits are determined on the basis of the IP Address hits during a timed interval
#
  class Visit  
    attr_accessor :ip, :start_dt, :end_dt, :expire_dt, :duration, :hits, :pages, :robots, :visitortype, :searchphrase

# This method calculates the rank
    def calculate_rank(pages, duration, visitortype)
      ranktotal = [pages,9].min*10 + [duration/60,9].min
      rank = ((ranktotal+10)/20).round
      rank = 1 if rank == 0
      rank = -rank if visitortype == "S"
      rank = 0 if visitortype == "D"
      return rank   
    end

# This method extracts the name of a downloaded file from the csuriquery value    
    def get_download(csuriquery, timetaken)
	  download = nil
	  if timetaken.to_i > 4000
        split_uri = csuriquery.split("file=")
        download = split_uri[1]
        p download
      end  
      return download   
    end

# The method completes the initialization and update methods
	def add_fields(csuriquery, timetaken, p_searchphrase, p_pageid)
      @searchphrase = p_searchphrase if p_searchphrase
	  @rank = calculate_rank(@pages, @duration, @visitortype)
      @pageids = []
      if p_pageid
        @pageids << p_pageid
      else
        z=(/(PageID)=(\d+)/).match(csuriquery)
        if z        
          p_pageid = z[2].to_i
          @pageids << p_pageid
          @download_file = get_download(csuriquery, timetaken) if p_pageid == @@download_page_number
        end  
      end  	
	end

# This method initializes the Visit object. Load object with parsed data
    def initialize(ip, log_dt, csuristem, csuriquery, timetaken, p_visitortype, p_pageflag, p_searchphrase, p_pageid)
      @ip = ip
      @start_dt = log_dt
      @expire_dt = @start_dt + @@visit_timeout
      @end_dt = @start_dt
      @duration = 0
      @hits = 0
      @pages = 0
      @pages = 1 if p_pageflag
      @visitortype = p_visitortype
      @visitortype = "S" if csuristem == "/robots.txt"
      @searchphrase = ""
      add_fields(csuriquery, timetaken, p_searchphrase, p_pageid)      
    end

# This method updates the Visit object with new parsed data
    def update(end_dt, csuriquery, timetaken, p_visitortype, p_pageflag, p_searchphrase, p_pageid)
      @end_dt = end_dt
      @duration = (@end_dt - @start_dt).to_i
      @hits = @hits + 1
      @pages = @pages + 1 if p_pageflag
      @visitortype = p_visitortype if @visitortype == "H"
      add_fields(csuriquery, timetaken, p_searchphrase, p_pageid)       
    end
    
    def sendoutput
#if @rank > 0
      iplong = @ip.to_s+"      "
      p ">"+iplong[0..14]+" "+@start_dt.to_s[0..18]+" "+@visitortype+" Hits> "+@hits.to_s+" Pgs> "+@pages.to_s+" Dur> "+@duration.to_s+" Rank> "+@rank.to_s
      p" Phrase> "+@searchphrase if @searchphrase.length > 0
      p @pageids if @pageids.length > 0
#end    
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
