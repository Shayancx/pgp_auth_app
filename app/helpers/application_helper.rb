# frozen_string_literal: true

# Helper methods for the main application
module ApplicationHelper
  # Get client IP address from request headers
  def client_ip
    env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip ||
      env['HTTP_X_REAL_IP'] ||
      env['REMOTE_ADDR'] ||
      'unknown'
  end

  # Generate CSRF tag for forms
  def csrf_tag
    Rack::Csrf.csrf_tag(env)
  end

  # Format rate limit message with time remaining
  def rate_limit_message(action, identifier)
    time_remaining = RateLimit.time_until_retry(identifier, action)
    action_text = {
      'login' => 'login attempts from your IP',
      'password' => 'password attempts for this account',
      'register' => 'registration attempts',
      'verify_pgp' => 'verification attempts',
      '2fa' => 'PGP attempts'
    }[action] || 'attempts'

    "Too many #{action_text}. Please try again in " \
      "#{RateLimit.format_time_remaining(time_remaining)}"
  end

  # Create secure session for authenticated user
  def create_secure_session(account_id)
    session_token = SessionManager.create_session(
      account_id,
      client_ip,
      env['HTTP_USER_AGENT']
    )
    session[:session_token] = session_token
    session[:rodauth_session_key] = account_id
    session_token
  end

  # Clear session and revoke token
  def clear_session_and_logout
    SessionManager.revoke_session(session[:session_token], 'user_logout') if session[:session_token]
    session.clear
  end
end
