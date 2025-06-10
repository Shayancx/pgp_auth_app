# frozen_string_literal: true

require_relative 'session_manager'

# Rack middleware for session validation and management
class SessionMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)
    validate_session_if_needed(env, request)
    @app.call(env)
  end

  private

  def validate_session_if_needed(env, request)
    return if skip_validation?(request.path)

    session_token = request.session[:session_token]
    return unless session_token

    account_id = SessionManager.validate_session(
      session_token,
      get_client_ip(env),
      env['HTTP_USER_AGENT']
    )

    if account_id
      env['authenticated_account_id'] = account_id
    else
      request.session.clear
      env['session_expired'] = true
    end
  end

  def skip_validation?(path)
    skip_paths = ['/', '/login', '/register', '/verify-pgp']
    skip_paths.include?(path) || path.start_with?('/public')
  end

  def get_client_ip(env)
    env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip ||
      env['HTTP_X_REAL_IP'] ||
      env['REMOTE_ADDR'] ||
      'unknown'
  end
end
