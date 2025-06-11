# frozen_string_literal: true

require 'roda'
require 'cgi'
require 'tilt/erb'
require_relative 'config/database'
require_relative 'lib/pgp_auth'
require_relative 'lib/rate_limit'
require_relative 'lib/session_manager'
require_relative 'lib/session_middleware'
require 'bcrypt'

# Load helpers
require_relative 'app/helpers/application_helper'

# Main Roda application for PGP-based authentication
class App < Roda
  include ApplicationHelper

  # CSRF error handling
  plugin :error_handler do |e|
    case e
    when Rack::Csrf::InvalidToken
      @error_message = "Security token invalid. Please try again."
      @error_type = "csrf"
      view "error"
    else
      raise e unless ENV["RACK_ENV"] == "production"
      @error_message = "An error occurred. Please try again."
      view "error"
    end
  end

  plugin :flash
  plugin :render, engine: 'erb', views: 'views'
  plugin :public
  plugin :default_headers, {
    'Content-Type' => 'text/html; charset=UTF-8',
    'X-Frame-Options' => 'DENY',
    'X-Content-Type-Options' => 'nosniff',
    'X-XSS-Protection' => '1; mode=block',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
    'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()'
  }

  # Session security middleware
  plugin :middleware do |middleware|
    middleware.use SessionMiddleware
  end

  # Error handling
  plugin :error_handler do |e|
    raise e unless ENV['RACK_ENV'] == 'production'

    @error_message = 'An error occurred. Please try again.'
    view 'error'
  end

  route do |r|
    r.root do
      view 'home'
    end

    # Authentication routes
    r.on 'login' do
      r.get do
        if RateLimit.blocked?(client_ip, 'login')
          RateLimit.time_until_retry(client_ip, 'login')
          @blocked_message = rate_limit_message('login', client_ip)
          view 'login_blocked'
        else
          view 'login'
        end
      end

      r.post do
        # Check rate limit first
        if RateLimit.blocked?(client_ip, 'login')
          flash['error'] = rate_limit_message('login', client_ip)
          r.redirect '/login'
        end

        username = r.params['username'].to_s.strip

        # FIXED: Only apply rate limiting after basic validation
        if username.empty?
          flash['error'] = 'Username is required'
          r.redirect '/login'
        end

        # NOW record the attempt after validation passes
        RateLimit.record_attempt(client_ip, 'login')

        # Always perform constant-time lookup
        account = DB[:accounts].where(username: username, verified: true).first

        # Generic error message to prevent username enumeration
        generic_error = 'Invalid credentials. Please check your username and try again.'

        unless account
          # Perform proper dummy password check to prevent timing attacks
          dummy_hash = BCrypt::Password.create("dummy_password_for_timing_#{SecureRandom.hex(8)}", cost: 12)
          BCrypt::Password.new(dummy_hash).is_password?("dummy_password_#{SecureRandom.hex(8)}")

          SessionManager.log_event(nil, 'login_failed', client_ip, env['HTTP_USER_AGENT'], {
                                     username: username,
                                     reason: 'invalid_username',
                                     success: false
                                   })

          flash['error'] = generic_error
          r.redirect '/login'
        end

        session[:login_username] = username

        if RateLimit.pgp_only_required?(username)
          session[:pgp_only_account_id] = account[:id]
          r.redirect '/login-pgp-only'
        else
          r.redirect '/login-password'
        end
      end
    end

    # Password authentication
    r.on 'login-password' do
      username = session[:login_username]
      r.redirect '/login' unless username

      @username = username

      r.get do
        if RateLimit.blocked?(username, 'password')
          @blocked_message = rate_limit_message('password', username)
          view 'password_blocked'
        else
          view 'login_password'
        end
      end

      r.post do
        if RateLimit.blocked?(username, 'password')
          flash['error'] = rate_limit_message('password', username)
          r.redirect '/login-password'
        end

        handle_password_authentication(r, username)
      end
    end

    # PGP-only authentication
    r.on 'login-pgp-only' do
      account_id = session[:pgp_only_account_id]
      r.redirect '/login' unless account_id

      @account = DB[:accounts].where(id: account_id).first
      r.redirect '/login' unless @account

      r.get do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          @blocked_message = rate_limit_message('2fa', account_id.to_s)
          view 'pgp_blocked'
        else
          generate_pgp_challenge(account_id)
          view 'login_pgp_only'
        end
      end

      r.post do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          flash['error'] = rate_limit_message('2fa', account_id.to_s)
          r.redirect '/login-pgp-only'
        end

        submitted_code = r.params['code'].to_s.strip
        
        # FIXED: Only record attempt after basic validation
        if submitted_code.empty?
          flash['error'] = 'Authentication code is required'
          r.redirect '/login-pgp-only'
        end

        RateLimit.record_attempt(account_id.to_s, '2fa')

        if verify_pgp_challenge(account_id, submitted_code)
          RateLimit.reset_password_failures(@account[:username])
          DB[:challenges].where(account_id: account_id).delete

          create_secure_session(account_id)

          flash['notice'] = 'PGP authentication successful - account security restored'
          r.redirect '/dashboard'
        else
          SessionManager.log_event(account_id, 'pgp_auth_failed', client_ip, env['HTTP_USER_AGENT'], {
                                     success: false
                                   })

          flash['error'] = 'Invalid authentication code. Please try again.'
          r.redirect '/login-pgp-only'
        end
      end
    end

    # 2FA authentication
    r.on 'pgp-2fa' do
      account_id = session[:pending_account_id]
      r.redirect '/login' unless account_id

      @account = DB[:accounts].where(id: account_id).first
      r.redirect '/login' unless @account

      r.get do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          @blocked_message = rate_limit_message('2fa', account_id.to_s)
          view 'pgp_blocked'
        else
          generate_pgp_challenge(account_id)
          view 'pgp_2fa'
        end
      end

      r.post do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          flash['error'] = rate_limit_message('2fa', account_id.to_s)
          r.redirect '/pgp-2fa'
        end

        submitted_code = r.params['code'].to_s.strip
        
        # FIXED: Only record attempt after basic validation
        if submitted_code.empty?
          flash['error'] = 'Authentication code is required'
          r.redirect '/pgp-2fa'
        end

        RateLimit.record_attempt(account_id.to_s, '2fa')

        if verify_pgp_challenge(account_id, submitted_code)
          DB[:challenges].where(account_id: account_id).delete

          create_secure_session(account_id)

          flash['notice'] = 'Authentication successful'
          r.redirect '/dashboard'
        else
          SessionManager.log_event(account_id, '2fa_failed', client_ip, env['HTTP_USER_AGENT'], {
                                     success: false
                                   })

          flash['error'] = 'Invalid code. Please try again.'
          r.redirect '/pgp-2fa'
        end
      end
    end

    # Registration routes
    r.on 'register' do
      r.get do
        if RateLimit.blocked?(client_ip, 'register')
          @blocked_message = rate_limit_message('register', client_ip)
          view 'register_blocked'
        else
          view 'register'
        end
      end

      r.post do
        handle_registration(r)
      end
    end

    # PGP verification
    r.on 'verify-pgp' do
      account_id = session[:unverified_account_id]
      unless account_id
        flash['error'] = 'No pending registration found'
        r.redirect '/register'
      end

      @account = DB[:accounts].where(id: account_id).first
      unless @account
        flash['error'] = 'Account not found'
        r.redirect '/register'
      end

      r.get do
        if RateLimit.blocked?(client_ip, 'verify_pgp')
          @blocked_message = rate_limit_message('verify_pgp', client_ip)
          view 'verify_blocked'
        else
          code = PgpAuth.random_code
          code_hash = PgpAuth.hash_challenge(code)

          DB[:accounts].where(id: account_id).update(
            verification_code: code_hash,
            verification_expires_at: Time.now + 600
          )

          @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)
          view 'verify_pgp'
        end
      end

      r.post do
        if RateLimit.blocked?(client_ip, 'verify_pgp')
          flash['error'] = rate_limit_message('verify_pgp', client_ip)
          r.redirect '/verify-pgp'
        end

        submitted_code = r.params['code'].to_s.strip

        # FIXED: Only record attempt after basic validation
        if submitted_code.empty?
          flash['error'] = 'Verification code is required'
          r.redirect '/verify-pgp'
        end

        RateLimit.record_attempt(client_ip, 'verify_pgp')

        account = DB[:accounts].where(id: account_id).first

        unless account[:verification_expires_at] &&
               account[:verification_expires_at] > Time.now
          flash['error'] = 'Verification expired. Please try again.'
          r.redirect '/verify-pgp'
        end

        submitted_hash = PgpAuth.hash_challenge(submitted_code)

        if secure_compare(submitted_hash, account[:verification_code])
          complete_verification(r, account_id)
        else
          SessionManager.log_event(account_id, 'verification_failed', client_ip, env['HTTP_USER_AGENT'], {
                                     success: false
                                   })

          flash['error'] = 'Invalid verification code. Please try again.'
          r.redirect '/verify-pgp'
        end
      end
    end

    # Dashboard routes
    r.on 'dashboard' do
      require_authentication(r) do |account|
        @account = account
        view 'dashboard'
      end
    end

    # Session management
    r.on 'sessions' do
      require_authentication(r) do |account|
        @account = account

        r.get do
          @sessions = SessionManager.get_active_sessions(account[:id])
          @current_token = session[:session_token]
          view 'sessions'
        end

        r.post 'revoke' do
          token_hash = r.params['token']
          if token_hash && !SessionManager.token_matches_session?(session[:session_token], token_hash)
            SessionManager.revoke_session_by_hash(token_hash, 'user_revoked')
            flash['notice'] = 'Session revoked successfully'
          end
          r.redirect '/sessions'
        end

        r.post 'revoke_all' do
          count = SessionManager.revoke_all_sessions(
            account[:id],
            session[:session_token]
          )
          flash['notice'] = "#{count} sessions revoked"
          r.redirect '/sessions'
        end
      end
    end

    # Security dashboard
    r.on 'security' do
      require_authentication(r) do |account|
        @account = account
        @audit_log = SessionManager.get_audit_log(account[:id])
        @active_sessions = SessionManager.get_active_sessions(account[:id])
        @rate_limit_status = {
          login: RateLimit.time_until_retry(client_ip, 'login'),
          password: RateLimit.time_until_retry(account[:username], 'password'),
          twofa: RateLimit.time_until_retry(account[:id].to_s, '2fa')
        }
        view 'security'
      end
    end

    # Logout
    r.on 'logout' do
      r.get { view 'logout' }

      r.post do
        clear_session_and_logout
        flash['notice'] = 'You have been logged out'
        r.redirect '/'
      end
    end
  end

  private

  def handle_password_authentication(r, username)
    password = r.params['password'].to_s

    if password.empty?
      flash['error'] = 'Password is required'
      r.redirect '/login-password'
    end

    account = DB[:accounts].where(username: username, verified: true).first

    if account && BCrypt::Password.new(account[:password_hash]) == password
      DB[:accounts].where(id: account[:id]).update(
        failed_login_count: 0,
        last_failed_login_at: nil
      )

      session[:pending_account_id] = account[:id]
      session.delete(:login_username)
      r.redirect '/pgp-2fa'
    else
      if account
        pgp_only_triggered = RateLimit.record_password_failure(username)

        DB[:accounts].where(id: account[:id]).update(
          failed_login_count: Sequel[:failed_login_count] + 1,
          last_failed_login_at: Time.now
        )

        if pgp_only_triggered
          flash['notice'] = 'Too many password failures. ' \
                            'This account now requires PGP-only authentication.'
          session[:pgp_only_account_id] = account[:id]
          session.delete(:login_username)
          r.redirect '/login-pgp-only'
        end
      end

      SessionManager.log_event(
        account ? account[:id] : nil,
        'password_failed',
        client_ip,
        env['HTTP_USER_AGENT'],
        { username: username, success: false }
      )

      flash['error'] = 'Invalid credentials. Please check your password and try again.'
      r.redirect '/login-password'
    end
  end

  def handle_registration(r)
    # Check rate limit first
    if RateLimit.blocked?(client_ip, 'register')
      flash['error'] = rate_limit_message('register', client_ip)
      r.redirect '/register'
    end

    # FIXED: Validate parameters first, THEN record attempt
    params = validate_registration_params(r)
    return unless params

    # NOW record the attempt since validation passed
    RateLimit.record_attempt(client_ip, 'register')

    begin
      fp = PgpAuth.import_and_fingerprint(params[:key_text])

      if DB[:accounts].where(fingerprint: fp).count.positive?
        flash['error'] = 'This PGP key is already registered'
        r.redirect '/register'
      end

      create_unverified_account(r, params, fp)
    rescue StandardError => e
      flash['error'] = "Invalid PGP key: #{e.message}"
      r.redirect '/register'
    end
  end

  def validate_registration_params(r)
    username = r.params['username'].to_s.strip
    password = r.params['password'].to_s
    key_text = r.params['public_key'].to_s.strip

    # FIXED: Don't penalize for basic form validation errors
    if username.empty? || password.empty? || key_text.empty?
      flash['error'] = 'All fields are required'
      r.redirect '/register'
      return nil
    end

    # Validate username format
    if (error = validate_username_format(username))
      flash['error'] = "Username #{error}"
      r.redirect '/register'
      return nil
    end

    # Validate password complexity
    password_errors = validate_password_complexity(password)
    unless password_errors.empty?
      flash['error'] = "Password must #{password_errors.join(', ')}"
      r.redirect '/register'
      return nil
    end

    # Check for existing username - this is the actual "attempt"
    if DB[:accounts].where(username: username).count.positive?
      flash['error'] = 'Username already taken'
      r.redirect '/register'
      return nil
    end

    { username: username, password: password, key_text: key_text }
  end

  def create_unverified_account(r, params, fingerprint)
    password_hash = BCrypt::Password.create(params[:password], cost: 12)

    id = DB[:accounts].insert(
      username: params[:username],
      password_hash: password_hash,
      public_key: params[:key_text],
      fingerprint: fingerprint,
      verified: false,
      pgp_only_mode: false,
      failed_password_count: 0,
      created_at: Time.now
    )

    SessionManager.log_event(id, 'account_created', client_ip, env['HTTP_USER_AGENT'], {
                               username: params[:username]
                             })

    session[:unverified_account_id] = id
    r.redirect '/verify-pgp'
  end

  def complete_verification(r, account_id)
    DB[:accounts].where(id: account_id).update(
      verified: true,
      verification_code: nil,
      verification_expires_at: nil
    )

    SessionManager.log_event(account_id, 'account_verified', client_ip, env['HTTP_USER_AGENT'])

    create_secure_session(account_id)

    flash['notice'] = 'Account created and verified successfully!'
    r.redirect '/dashboard'
  end

  def generate_pgp_challenge(account_id)
    # Clean up old challenges
    DB[:challenges].where(account_id: account_id)
                   .where { expires_at < Time.now }
                   .delete

    code = PgpAuth.random_code
    code_hash = PgpAuth.hash_challenge(code)

    DB[:challenges].insert(
      account_id: account_id,
      code_hash: code_hash,
      expires_at: Time.now + 300,
      created_at: Time.now
    )

    @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)
  end

  def verify_pgp_challenge(account_id, submitted_code)
    row = DB[:challenges].where(account_id: account_id)
                         .where { expires_at > Time.now }
                         .reverse(:id).first

    return false unless row

    submitted_hash = PgpAuth.hash_challenge(submitted_code)
    secure_compare(submitted_hash, row[:code_hash])
  end

  def require_authentication(r)
    r.redirect '/login' unless session[:auth_account_id]

    account_id = session[:auth_account_id]
    account = DB[:accounts].where(id: account_id).first

    unless account
      clear_session_and_logout
      r.redirect '/login'
    end

    yield account
  end
end

# Security validation on startup
if ENV['RACK_ENV'] == 'production'
  require_relative 'lib/environment_validator'
  EnvironmentValidator.validate!
end

  # SECURITY HARDENED: Enhanced input validation
  def validate_and_sanitize_input(params)
    sanitized = {}
    
    params.each do |key, value|
      next unless value.is_a?(String)
      
      # Length limits
      case key
      when 'username'
        value = value.slice(0, 50)
      when 'password' 
        value = value.slice(0, 128)
      when 'public_key'
        value = value.slice(0, 100_000)
      when 'code'
        value = value.slice(0, 100)
      else
        value = value.slice(0, 1000)
      end
      
      # Sanitization
      sanitized[key] = sanitize_input(value)
    end
    
    sanitized
  end

  # SECURITY HARDENED: Enhanced error handling
  def handle_error_securely(error, context = 'operation')
    # Log full error for debugging
    puts "ERROR in #{context}: #{error.message}" if ENV['RACK_ENV'] == 'development'
    
    # Return generic error to user
    case error.message
    when /PGP/i
      'PGP operation failed. Please check your key and try again.'
    when /password/i
      'Authentication failed. Please check your credentials.'
    when /network/i, /timeout/i
      'Service temporarily unavailable. Please try again later.'
    else
      'An error occurred. Please try again.'
    end
  end
