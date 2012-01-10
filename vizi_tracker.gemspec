require 'rubygems'

spec = Gem::Specification.new do |s|
  s.name = 'vizi_tracker'
  s.version = '0.2.0'
  s.summary = "Visit tracking from Apache or IIS web log files"
  s.description = "This module provides a set of classes to support the parsing of web log files and
    the creation of visits from the individual parsed web log records.
    
    The LogFormat and LogParser classes were derived in part from an Apache logger application
    developed by Jan Wikholm. These two classes were extended to support both Apache and IIS
    web logs. The details from the web logs are assembled to compose Visit objects and Visit 
    history detail"
  s.files = Dir.glob("**/**/**")
  s.test_files = Dir.glob("test/*_test.rb")
  s.author = "Al Kivi"
  s.homepage = "http://www.vizitrax.com"
  s.email = "al.kivi@yahoo.com"
  s.has_rdoc = true
  s.required_ruby_version = '>= 1.8.2'
end
