# frozen_string_literal: true

require 'ipaddr'

# Helper methods for the main application
module ApplicationHelper
  # Get client IP address with spoofing protection
  def client_ip
    # In production, only trust direct connection or properly configured proxy
    if ENV['RACK_ENV'] == 'production' && ENV['TRUSTED_PROXY_IP']
      begin
        trusted_proxy = IPAddr.new(ENV['TRUSTED_PROXY_IP'])
        remote_ip = IPAddr.new(env['REMOTE_ADDR'] || '0.0.0.0')

        if trusted_proxy.include?(remote_ip)
          # Only trust X-Forwarded-For from trusted proxy
          env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip || env['REMOTE_ADDR']
        else
          env['REMOTE_ADDR']
        end
      rescue IPAddr::InvalidAddressError
        env['REMOTE_ADDR'] || 'unknown'
      end
    else
      # Development/test mode or no trusted proxy configured
      env['REMOTE_ADDR'] || 'unknown'
    end
  end

  # Generate CSRF protection token tag
  def csrf_tag
    Rack::Csrf.tag(env)
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

  # Create secure session for authenticated user
  def create_secure_session(account_id)
    # Regenerate session ID to prevent fixation
    env['rack.session.options'][:renew] = true if env['rack.session.options']

    session_token = SessionManager.create_session(
      account_id,
      client_ip,
      env['HTTP_USER_AGENT']
    )
    session[:session_token] = session_token
    session[:auth_account_id] = account_id

    # Clear any temporary session data
    session.delete(:login_username)
    session.delete(:pending_account_id)
    session.delete(:unverified_account_id)
    session.delete(:pgp_only_account_id)

    session_token
  end

  # Clear session and revoke token
  def clear_session_and_logout
    SessionManager.revoke_session(session[:session_token], 'user_logout') if session[:session_token]
    env['rack.session.options'][:drop] = true if env['rack.session.options']
    session.clear
  end

  # Constant-time string comparison
  def secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    l = a.unpack('C*')
    r = b.unpack('C*')
    result = 0
    l.zip(r) { |x, y| result |= x ^ y }
    result.zero?
  end

  # Validate password complexity
  def validate_password_complexity(password)
    errors = []
    errors << 'be at least 12 characters long' if password.length < 12
    errors << 'contain at least one uppercase letter' unless password =~ /[A-Z]/
    errors << 'contain at least one lowercase letter' unless password =~ /[a-z]/
    errors << 'contain at least one number' unless password =~ /\d/
    errors << 'contain at least one special character' unless password =~ /[^A-Za-z0-9]/
    errors << 'not contain spaces' if password.include?(' ')
    errors
  end

  # Validate username format
  def validate_username_format(username)
    return 'must be between 3 and 50 characters' if username.length < 3 || username.length > 50
    return 'must start with a letter' unless username =~ /\A[a-zA-Z]/
    return 'must contain only letters, numbers, underscore and hyphen' unless username =~ /\A[a-zA-Z][a-zA-Z0-9_-]*\z/
    return 'must not end with special characters' if username =~ /[_-]\z/

    nil
  end
end
