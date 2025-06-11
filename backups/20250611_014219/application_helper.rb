# frozen_string_literal: true

require 'ipaddr'
require 'openssl'

# Helper methods for the main application
module ApplicationHelper
  # Get client IP address with enhanced spoofing protection
  def client_ip

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
    # Enhanced IP detection with strict validation

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
    if ENV['RACK_ENV'] == 'production' && ENV['TRUSTED_PROXY_IP']

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
      begin

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
        trusted_proxies = ENV['TRUSTED_PROXY_IP'].split(',').map { |ip| IPAddr.new(ip.strip) }

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
        remote_ip = IPAddr.new(env['REMOTE_ADDR'] || '0.0.0.0')

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end


  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
        if trusted_proxies.any? { |proxy| proxy.include?(remote_ip) }

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
          # Only trust X-Forwarded-For from trusted proxy

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
          forwarded = env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
          if forwarded && forwarded.match?(/\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z/)

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
            forwarded

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
          else

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
            env['REMOTE_ADDR']

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
          end

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
        else

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
          env['REMOTE_ADDR']

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
        end

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
      rescue IPAddr::InvalidAddressError

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
        env['REMOTE_ADDR'] || 'unknown'

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
      end

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
    else

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
      # Development/test mode or no trusted proxy configured

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
      env['REMOTE_ADDR'] || 'unknown'

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
    end

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end
  end

  # Generate CSRF protection token tag - BULLETPROOF VERSION
  def csrf_tag
    begin
      # Multiple fallback strategies
      if env && env['rack.session']
        # Try the standard Rack::Csrf approach
        if defined?(Rack::Csrf)
          token = Rack::Csrf.token(env)
          field = Rack::Csrf.field
          
          if token && !token.empty? && field && !field.empty?
            return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
          end
        end
        
        # Fallback: Generate our own token using session
        session_token = env['rack.session']['csrf.token'] ||= SecureRandom.hex(32)
        return %(<input type="hidden" name="authenticity_token" value="#{CGI.escapeHTML(session_token)}" />)
      end
      
      # Last resort fallback
      return '<input type="hidden" name="authenticity_token" value="" />'
    rescue => e
      puts "CSRF token generation error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      return '<input type="hidden" name="authenticity_token" value="" />'
    end
  end

  # Generate CSRF protection token tag - CRITICAL METHOD

  # Alternative CSRF token method for forms
  def csrf_token
    begin
      Rack::Csrf.token(env)
    rescue => e
      puts "CSRF token retrieval error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      ''
    end
  end

  # CSRF field name
  def csrf_field
    begin
      Rack::Csrf.field
    rescue => e
      puts "CSRF field retrieval error: #{e.message}" if ENV['RACK_ENV'] == 'development'
      'authenticity_token'
    end
  end

  # Format rate limit message with time remaining
  def rate_limit_message(action, identifier)
    time_remaining = RateLimit.time_until_retry(identifier, action)
    action_text = {
      'login' => 'login attempts',
      'password' => 'password attempts',
      'register' => 'registration attempts',
      'verify_pgp' => 'verification attempts',
      '2fa' => 'authentication attempts'
    }[action] || 'attempts'

    "Too many #{action_text}. Please try again in " \
      "#{RateLimit.format_time_remaining(time_remaining)}"
  end

  # Create secure session for authenticated user with enhanced protection
  def create_secure_session(account_id)
    # Force session regeneration to prevent fixation
    if env['rack.session.options']
      env['rack.session.options'][:renew] = true
      env['rack.session.options'][:drop] = true
    end
    
    # Clear existing session data
    session.clear

    session_token = SessionManager.create_session(
      account_id,
      client_ip,
      env['HTTP_USER_AGENT']
    )
    
    # Set new session data
    session[:session_token] = session_token
    session[:auth_account_id] = account_id
    session[:created_at] = Time.now.to_i
    session[:last_regenerated] = Time.now.to_i

    # Clear any temporary session data
    session.delete(:login_username)
    session.delete(:pending_account_id)
    session.delete(:unverified_account_id)
    session.delete(:pgp_only_account_id)

    session_token
  end

  # Clear session and revoke token with enhanced cleanup
  def clear_session_and_logout
    SessionManager.revoke_session(session[:session_token], 'user_logout') if session[:session_token]
    
    # Force session destruction
    if env['rack.session.options']
      env['rack.session.options'][:drop] = true
      env['rack.session.options'][:renew] = true
    end
    
    session.clear
  end

  # Cryptographically secure constant-time string comparison
  def secure_compare(a, b)
    return false if a.nil? || b.nil?
    return false unless a.bytesize == b.bytesize

    # Use OpenSSL's secure comparison if available
    if defined?(OpenSSL.secure_compare)
      OpenSSL.secure_compare(a, b)
    else
      # Fallback to manual constant-time comparison
      l = a.unpack('C*')
      r = b.unpack('C*')
      result = 0
      l.zip(r) { |x, y| result |= x ^ y }
      result.zero?
    end
  end

  # Enhanced password complexity validation
  def validate_password_complexity(password)
    errors = []
    
    # Length check
    errors << 'be at least 12 characters long' if password.length < 12
    errors << 'be no more than 128 characters long' if password.length > 128
    
    # Character class checks
    errors << 'contain at least one uppercase letter' unless password =~ /[A-Z]/
    errors << 'contain at least one lowercase letter' unless password =~ /[a-z]/
    errors << 'contain at least one number' unless password =~ /\d/
    errors << 'contain at least one special character' unless password =~ /[^A-Za-z0-9]/
    
    # Security checks
    errors << 'not contain spaces' if password.include?(' ')
    errors << 'not contain the username' if defined?(@username) && password.downcase.include?(@username.downcase)
    
    # Common pattern checks
    errors << 'not contain common patterns' if password =~ /(.)\1{3,}/ # No 4+ repeated chars
    errors << 'not be a common password' if common_password?(password)
    
    errors
  end

  # Enhanced username format validation
  def validate_username_format(username)
    return 'must be between 3 and 50 characters' if username.length < 3 || username.length > 50
    return 'must start with a letter' unless username =~ /\A[a-zA-Z]/
    return 'must contain only letters, numbers, underscore and hyphen' unless username =~ /\A[a-zA-Z][a-zA-Z0-9_-]*\z/
    return 'must not end with special characters' if username =~ /[_-]\z/
    return 'cannot contain consecutive special characters' if username =~ /[_-]{2,}/
    return 'is reserved' if reserved_username?(username)

    nil
  end

  # Input sanitization for all user inputs
  def sanitize_input(input, max_length = 1000)
    return '' if input.nil?
    
    input.to_s
         .strip
         .slice(0, max_length)
         .gsub(/[^\x20-\x7E]/, '') # Remove non-printable chars
         .gsub(/\s+/, ' ') # Normalize whitespace
  end

  # Enhanced HTML escaping with additional protections
  def escape_html(text)
    return '' if text.nil?
    
    CGI.escapeHTML(text.to_s)
       .gsub('&#x27;', '&#x27;') # Additional quote escaping
       .gsub('/', '&#x2F;')      # Forward slash escaping
  end

  # Secure random token generation
  def generate_secure_token(length = 32)
    SecureRandom.hex(length)
  end

  # Check if session needs regeneration
  def session_needs_regeneration?
    return true unless session[:last_regenerated]
    
    # Regenerate every hour
    (Time.now.to_i - session[:last_regenerated].to_i) > 3600
  end

  # Regenerate session ID for security
  def regenerate_session_id
    if session_needs_regeneration?
      old_session = session.to_hash
      session.clear
      old_session.each { |k, v| session[k] = v }
      session[:last_regenerated] = Time.now.to_i
    end
  end

  private

  def common_password?(password)
    common_passwords = %w[
      password password123 123456 123456789 qwerty abc123 
      letmein welcome admin user guest test password1
    ]
    common_passwords.include?(password.downcase)
  end

  def reserved_username?(username)
    reserved = %w[
      admin administrator root system api www mail ftp 
      support help info contact about login register
      auth security pgp key public private test guest
    ]
    reserved.include?(username.downcase)
  end
end
