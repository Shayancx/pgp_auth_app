# frozen_string_literal: true

require 'ipaddr'
require 'openssl'
require 'securerandom'
require 'cgi'

# Helper methods for the main application - SECURITY HARDENED
module ApplicationHelper
  MAX_INPUT_LENGTH = 10000
  MAX_USERNAME_LENGTH = 50
  MAX_PASSWORD_LENGTH = 128
  
  # Get client IP address with enhanced spoofing protection
  def client_ip
    if ENV['RACK_ENV'] == 'production' && ENV['TRUSTED_PROXY_IP']
      begin
        trusted_proxies = ENV['TRUSTED_PROXY_IP'].split(',').map { |ip| IPAddr.new(ip.strip) }
        remote_ip = IPAddr.new(env['REMOTE_ADDR'] || '0.0.0.0')

        if trusted_proxies.any? { |proxy| proxy.include?(remote_ip) }
          forwarded = env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip
          if forwarded && forwarded.match?(/\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\z/)
            forwarded
          else
            env['REMOTE_ADDR']
          end
        else
          env['REMOTE_ADDR']
        end
      rescue IPAddr::InvalidAddressError
        env['REMOTE_ADDR'] || 'unknown'
      end
    else
      env['REMOTE_ADDR'] || 'unknown'
    end
  end

  # SECURITY HARDENED: Generate CSRF protection token tag
  def csrf_tag
    return '<input type="hidden" name="authenticity_token" value="MISSING_SESSION" />' unless env && env['rack.session']
    
    begin
      if defined?(Rack::Csrf)
        token = Rack::Csrf.token(env)
        field = Rack::Csrf.field
        
        # SECURE: Fail if token generation fails
        raise 'CSRF token generation failed' if token.nil? || token.empty? || field.nil? || field.empty?
        
        return %(<input type="hidden" name="#{CGI.escapeHTML(field)}" value="#{CGI.escapeHTML(token)}" />)
      else
        raise 'Rack::Csrf not available'
      end
    rescue => e
      # SECURE: Log error and fail securely
      puts "CRITICAL CSRF ERROR: #{e.message}" if ENV['RACK_ENV'] == 'development'
      raise 'CSRF protection unavailable' if ENV['RACK_ENV'] == 'production'
      return '<input type="hidden" name="authenticity_token" value="ERROR" />'
    end
  end

  # SECURE: Alternative CSRF methods with proper error handling
  def csrf_token
    Rack::Csrf.token(env)
  rescue => e
    raise 'CSRF token unavailable' if ENV['RACK_ENV'] == 'production'
    ''
  end

  def csrf_field
    Rack::Csrf.field
  rescue => e
    raise 'CSRF field unavailable' if ENV['RACK_ENV'] == 'production'
    'authenticity_token'
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

  # SECURITY HARDENED: Create secure session 
  def create_secure_session(account_id)
    # Force session regeneration to prevent fixation
    if env['rack.session.options']
      env['rack.session.options'][:renew] = true
      env['rack.session.options'][:drop] = true
    end
    
    session.clear

    session_token = SessionManager.create_session(
      account_id,
      client_ip,
      env['HTTP_USER_AGENT']
    )
    
    session[:session_token] = session_token
    session[:auth_account_id] = account_id
    session[:created_at] = Time.now.to_i
    session[:last_regenerated] = Time.now.to_i

    # Clear temporary session data
    session.delete(:login_username)
    session.delete(:pending_account_id)
    session.delete(:unverified_account_id)
    session.delete(:pgp_only_account_id)

    session_token
  end

  # Clear session and revoke token with enhanced cleanup
  def clear_session_and_logout
    SessionManager.revoke_session(session[:session_token], 'user_logout') if session[:session_token]
    
    if env['rack.session.options']
      env['rack.session.options'][:drop] = true
      env['rack.session.options'][:renew] = true
    end
    
    session.clear
  end

  # SECURITY HARDENED: Cryptographically secure constant-time string comparison
  def secure_compare(a, b)
    return false if a.nil? || b.nil?
    return false unless a.bytesize == b.bytesize

    if defined?(OpenSSL.secure_compare)
      OpenSSL.secure_compare(a, b)
    else
      # Constant-time comparison fallback
      result = 0
      a.bytes.zip(b.bytes) { |x, y| result |= x ^ y }
      result.zero?
    end
  end

  # SECURITY HARDENED: Enhanced password complexity validation
  def validate_password_complexity(password)
    errors = []
    
    return ['be provided'] if password.nil? || password.empty?
    return ['be no more than 128 characters'] if password.length > MAX_PASSWORD_LENGTH
    
    errors << 'be at least 12 characters long' if password.length < 12
    errors << 'contain at least one uppercase letter' unless password =~ /[A-Z]/
    errors << 'contain at least one lowercase letter' unless password =~ /[a-z]/
    errors << 'contain at least one number' unless password =~ /\d/
    errors << 'contain at least one special character' unless password =~ /[^A-Za-z0-9]/
    errors << 'not contain spaces' if password.include?(' ')
    errors << 'not contain common patterns' if password =~ /(.)\1{3,}/
    errors << 'not be a common password' if common_password?(password)
    
    errors
  end

  # SECURITY HARDENED: Enhanced username format validation
  def validate_username_format(username)
    return 'be provided' if username.nil? || username.empty?
    return 'be no more than 50 characters' if username.length > MAX_USERNAME_LENGTH
    return 'be between 3 and 50 characters' if username.length < 3
    return 'start with a letter' unless username =~ /\A[a-zA-Z]/
    return 'contain only letters, numbers, underscore and hyphen' unless username =~ /\A[a-zA-Z][a-zA-Z0-9_-]*\z/
    return 'not end with special characters' if username =~ /[_-]\z/
    return 'not contain consecutive special characters' if username =~ /[_-]{2,}/
    return 'is reserved' if reserved_username?(username)

    nil
  end

  # SECURITY HARDENED: Comprehensive input sanitization
  def sanitize_input(input, max_length = MAX_INPUT_LENGTH)
    return '' if input.nil?
    
    sanitized = input.to_s
                    .strip
                    .slice(0, max_length)
                    .gsub(/[^\x20-\x7E]/, '') # Remove non-printable chars
                    .gsub(/\s+/, ' ') # Normalize whitespace
                    .gsub(/[<>'"&]/, '') # Remove potential XSS chars
    
    sanitized
  end

  # SECURITY HARDENED: Enhanced HTML escaping
  def escape_html(text)
    return '' if text.nil?
    
    CGI.escapeHTML(text.to_s)
       .gsub("'", '&#x27;')
       .gsub('/', '&#x2F;')
       .gsub('`', '&#x60;')
  end

  # SECURITY HARDENED: Secure random token generation
  def generate_secure_token(length = 32)
    SecureRandom.hex(length)
  end

  private

  def common_password?(password)
    common_passwords = %w[
      password password123 123456 123456789 qwerty abc123 
      letmein welcome admin user guest test password1
      12345678 111111 dragon 1234567890 sunshine
    ]
    common_passwords.include?(password.downcase)
  end

  def reserved_username?(username)
    reserved = %w[
      admin administrator root system api www mail ftp 
      support help info contact about login register
      auth security pgp key public private test guest
      null undefined console log error debug trace
    ]
    reserved.include?(username.downcase)
  end
end
