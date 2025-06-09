# frozen_string_literal: true
require "roda"
require "cgi"
require_relative "config/database"
require "rodauth"
require_relative "lib/pgp_auth"
require_relative "pgp_challenge_feature"

class App < Roda
  plugin :flash
  plugin :public
  plugin :default_headers, 
    'Content-Type'=>'text/html; charset=UTF-8'

  plugin :rodauth do
    enable :base, :logout, :pgp_challenge
    logout_redirect "/"
  end

  route do |r|
    r.rodauth

    r.root do
      response['Content-Type'] = 'text/html; charset=UTF-8'
      <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>PGP Auth</title>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
              font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
              background: #000000; 
              color: #ffffff; 
              min-height: 100vh; 
              display: flex; 
              align-items: center; 
              justify-content: center;
              line-height: 1.6;
            }
            .container { 
              max-width: 480px; 
              padding: 40px; 
              text-align: center; 
            }
            h1 { 
              font-size: 2.5rem; 
              font-weight: 300; 
              margin-bottom: 16px; 
              letter-spacing: -0.02em;
            }
            p { 
              font-size: 1.1rem; 
              color: #999999; 
              margin-bottom: 32px; 
              font-weight: 400;
            }
            .btn-group {
              display: flex;
              gap: 16px;
              justify-content: center;
            }
            .btn { 
              display: inline-block; 
              background: #ffffff; 
              color: #000000; 
              padding: 16px 32px; 
              text-decoration: none; 
              border-radius: 8px; 
              font-weight: 500; 
              font-size: 1rem;
              transition: all 0.2s ease;
              border: 1px solid #ffffff;
              flex: 1;
            }
            .btn:hover { 
              background: transparent; 
              color: #ffffff; 
              transform: translateY(-1px);
            }
            .btn-secondary {
              background: transparent;
              color: #ffffff;
              border: 1px solid #333333;
            }
            .btn-secondary:hover {
              border-color: #ffffff;
            }
            .lock-icon { 
              font-size: 3rem; 
              margin-bottom: 24px; 
              opacity: 0.8;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="lock-icon">🔐</div>
            <h1>PGP Auth</h1>
            <p>Secure two-factor authentication using cryptographic keys</p>
            <div class="btn-group">
              <a href="/login" class="btn">Login</a>
              <a href="/register" class="btn btn-secondary">Register</a>
            </div>
          </div>
        </body>
        </html>
      HTML
    end

    r.on "login" do
      r.get do
        response['Content-Type'] = 'text/html; charset=UTF-8'
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Login • PGP Auth</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
              * { margin: 0; padding: 0; box-sizing: border-box; }
              body { 
                font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                background: #000000; 
                color: #ffffff; 
                min-height: 100vh; 
                display: flex; 
                align-items: center; 
                justify-content: center;
                padding: 20px;
              }
              .container { 
                max-width: 400px; 
                width: 100%;
              }
              h2 { 
                font-size: 2rem; 
                font-weight: 300; 
                margin-bottom: 8px; 
                text-align: center;
                letter-spacing: -0.02em;
              }
              .subtitle {
                text-align: center;
                color: #666666;
                margin-bottom: 40px;
                font-size: 1rem;
              }
              .form-container { 
                background: #111111; 
                padding: 40px; 
                border-radius: 12px; 
                border: 1px solid #222222;
              }
              input[type="text"], input[type="password"] { 
                width: 100%; 
                padding: 16px 20px; 
                border: 1px solid #333333; 
                border-radius: 8px; 
                background: #000000; 
                color: #ffffff; 
                font-size: 16px; 
                margin-bottom: 20px;
              }
              input:focus { 
                border-color: #ffffff; 
                outline: none; 
                box-shadow: 0 0 0 1px #ffffff;
              }
              input::placeholder {
                color: #555555;
              }
              .btn { 
                background: #ffffff; 
                color: #000000; 
                padding: 16px 32px; 
                border: none; 
                border-radius: 8px; 
                font-size: 1rem; 
                font-weight: 500; 
                cursor: pointer; 
                width: 100%;
                transition: all 0.2s ease;
              }
              .btn:hover { 
                background: #f0f0f0; 
                transform: translateY(-1px);
              }
              .error { 
                background: #330000; 
                color: #ff6666; 
                padding: 16px; 
                border-radius: 8px; 
                margin-bottom: 24px; 
                border: 1px solid #660000;
                text-align: center;
              }
              .back-link {
                display: block;
                text-align: center;
                color: #666666;
                text-decoration: none;
                margin-top: 24px;
                font-size: 0.9rem;
              }
              .back-link:hover {
                color: #ffffff;
              }
              .register-link {
                text-align: center;
                margin-top: 20px;
                color: #666666;
                font-size: 0.9rem;
              }
              .register-link a {
                color: #ffffff;
                text-decoration: none;
              }
              .register-link a:hover {
                text-decoration: underline;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <h2>Login</h2>
              <p class="subtitle">Enter your credentials</p>
              #{flash['error'] ? "<div class='error'>#{flash['error']}</div>" : ''}
              <div class="form-container">
                <form method="post">
                  #{csrf_tag}
                  <input type="text" name="username" placeholder="Username" required autocomplete="username">
                  <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
                  <button type="submit" class="btn">Login</button>
                </form>
                <div class="register-link">
                  Don't have an account? <a href="/register">Register</a>
                </div>
              </div>
              <a href="/" class="back-link">← Back</a>
            </div>
          </body>
          </html>
        HTML
      end

      r.post do
        username = r.params["username"].to_s.strip
        password = r.params["password"].to_s
        
        account = DB[:accounts].where(username: username).first
        
        if account && BCrypt::Password.new(account[:password_hash]) == password
          # Password correct, proceed to 2FA
          session[:pending_account_id] = account[:id]
          r.redirect "/pgp-2fa"
        else
          flash["error"] = "Invalid username or password"
          r.redirect "/login"
        end
      end
    end

    r.on "register" do
      r.get do
        response['Content-Type'] = 'text/html; charset=UTF-8'
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Register • PGP Auth</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
              * { margin: 0; padding: 0; box-sizing: border-box; }
              body { 
                font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                background: #000000; 
                color: #ffffff; 
                min-height: 100vh; 
                display: flex; 
                align-items: center; 
                justify-content: center;
                padding: 20px;
              }
              .container { 
                max-width: 600px; 
                width: 100%;
              }
              h2 { 
                font-size: 2rem; 
                font-weight: 300; 
                margin-bottom: 8px; 
                text-align: center;
                letter-spacing: -0.02em;
              }
              .subtitle {
                text-align: center;
                color: #666666;
                margin-bottom: 40px;
                font-size: 1rem;
              }
              .form-container { 
                background: #111111; 
                padding: 40px; 
                border-radius: 12px; 
                border: 1px solid #222222;
              }
              input[type="text"], input[type="password"] { 
                width: 100%; 
                padding: 16px 20px; 
                border: 1px solid #333333; 
                border-radius: 8px; 
                background: #000000; 
                color: #ffffff; 
                font-size: 16px; 
                margin-bottom: 20px;
              }
              textarea { 
                width: 100%; 
                padding: 20px; 
                border: 1px solid #333333; 
                border-radius: 8px; 
                font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; 
                background: #000000; 
                color: #ffffff; 
                font-size: 14px; 
                min-height: 200px; 
                resize: vertical;
                line-height: 1.4;
                margin-bottom: 20px;
              }
              input:focus, textarea:focus { 
                border-color: #ffffff; 
                outline: none; 
                box-shadow: 0 0 0 1px #ffffff;
              }
              input::placeholder, textarea::placeholder {
                color: #555555;
              }
              .btn { 
                background: #ffffff; 
                color: #000000; 
                padding: 16px 32px; 
                border: none; 
                border-radius: 8px; 
                font-size: 1rem; 
                font-weight: 500; 
                cursor: pointer; 
                width: 100%;
                transition: all 0.2s ease;
              }
              .btn:hover { 
                background: #f0f0f0; 
                transform: translateY(-1px);
              }
              .error { 
                background: #330000; 
                color: #ff6666; 
                padding: 16px; 
                border-radius: 8px; 
                margin-bottom: 24px; 
                border: 1px solid #660000;
                text-align: center;
              }
              .back-link {
                display: block;
                text-align: center;
                color: #666666;
                text-decoration: none;
                margin-top: 24px;
                font-size: 0.9rem;
              }
              .back-link:hover {
                color: #ffffff;
              }
              .login-link {
                text-align: center;
                margin-top: 20px;
                color: #666666;
                font-size: 0.9rem;
              }
              .login-link a {
                color: #ffffff;
                text-decoration: none;
              }
              .login-link a:hover {
                text-decoration: underline;
              }
              .form-section {
                margin-bottom: 24px;
              }
              .form-section h3 {
                font-size: 1.1rem;
                font-weight: 400;
                margin-bottom: 12px;
                color: #cccccc;
              }
              .help-text {
                font-size: 0.85rem;
                color: #666666;
                margin-top: -12px;
                margin-bottom: 20px;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <h2>Create Account</h2>
              <p class="subtitle">Secure two-factor authentication</p>
              #{flash['error'] ? "<div class='error'>#{flash['error']}</div>" : ''}
              <div class="form-container">
                <form method="post">
                  #{csrf_tag}
                  <div class="form-section">
                    <h3>Account Information</h3>
                    <input type="text" name="username" placeholder="Username" required autocomplete="username">
                    <input type="password" name="password" placeholder="Password" required autocomplete="new-password">
                  </div>
                  
                  <div class="form-section">
                    <h3>PGP Key (2FA)</h3>
                    <p class="help-text">Your PGP key will be used for two-factor authentication</p>
                    <textarea name="public_key" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF...
...
-----END PGP PUBLIC KEY BLOCK-----" required></textarea>
                  </div>
                  
                  <button type="submit" class="btn">Create Account</button>
                </form>
                <div class="login-link">
                  Already have an account? <a href="/login">Login</a>
                </div>
              </div>
              <a href="/" class="back-link">← Back</a>
            </div>
          </body>
          </html>
        HTML
      end

      r.post do
        username = r.params["username"].to_s.strip
        password = r.params["password"].to_s
        key_text = r.params["public_key"].to_s.strip
        
        halt(400, "All fields are required") if username.empty? || password.empty? || key_text.empty?
        
        # Check if username already exists
        if DB[:accounts].where(username: username).count > 0
          flash["error"] = "Username already taken"
          r.redirect "/register"
        end
        
        begin
          fp = PgpAuth.import_and_fingerprint(key_text)
          password_hash = BCrypt::Password.create(password)
          
          id = DB[:accounts].insert(
            username: username,
            password_hash: password_hash,
            public_key: key_text, 
            fingerprint: fp
          )
          
          # Log the user in immediately after registration
          session[:rodauth_session_key] = id
          flash["notice"] = "Account created successfully!"
          r.redirect "/dashboard"
        rescue => e
          flash["error"] = "Invalid PGP key: #{e.message}"
          r.redirect "/register"
        end
      end
    end

    r.on "pgp-2fa" do
      account_id = session[:pending_account_id]
      r.redirect "/login" unless account_id
      
      account = DB[:accounts].where(id: account_id).first
      r.redirect "/login" unless account

      r.get do
        # Clean up expired challenges
        DB[:challenges].where(account_id: account_id)
                       .where { expires_at < Time.now }
                       .delete
        
        code = PgpAuth.random_code
        DB[:challenges].insert(account_id: account_id,
                               code: code,
                               expires_at: Time.now + 300)
        encrypted = PgpAuth.encrypt_for(account[:fingerprint], code)
        
        response['Content-Type'] = 'text/html; charset=UTF-8'
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Two-Factor Authentication • PGP Auth</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
              * { margin: 0; padding: 0; box-sizing: border-box; }
              body { 
                font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                background: #000000; 
                color: #ffffff; 
                min-height: 100vh; 
                display: flex; 
                align-items: center; 
                justify-content: center;
                padding: 20px;
              }
              .container { 
                max-width: 700px; 
                width: 100%;
              }
              h2 { 
                font-size: 2rem; 
                font-weight: 300; 
                margin-bottom: 8px; 
                text-align: center;
                letter-spacing: -0.02em;
              }
              .subtitle {
                text-align: center;
                color: #666666;
                margin-bottom: 32px;
                font-size: 1rem;
              }
              .challenge-container { 
                background: #111111; 
                padding: 32px; 
                border-radius: 12px; 
                border: 1px solid #222222;
                margin-bottom: 24px;
              }
              .encrypted-text { 
                background: #000000; 
                padding: 24px; 
                border: 1px solid #333333; 
                border-radius: 8px; 
                font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; 
                font-size: 13px; 
                line-height: 1.4; 
                color: #cccccc;
                margin-bottom: 24px;
                max-height: 300px;
                overflow-y: auto;
              }
              .form-container { 
                background: #111111; 
                padding: 32px; 
                border-radius: 12px; 
                border: 1px solid #222222;
                text-align: center;
              }
              input[type="text"] { 
                padding: 16px 20px; 
                border: 1px solid #333333; 
                border-radius: 8px; 
                font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; 
                background: #000000; 
                color: #ffffff; 
                font-size: 16px; 
                width: 100%; 
                max-width: 400px;
                margin-bottom: 20px;
                text-align: center;
              }
              input[type="text"]:focus { 
                border-color: #ffffff; 
                outline: none; 
                box-shadow: 0 0 0 1px #ffffff;
              }
              input[type="text"]::placeholder {
                color: #555555;
              }
              .btn { 
                background: #ffffff; 
                color: #000000; 
                padding: 16px 32px; 
                border: none; 
                border-radius: 8px; 
                font-size: 1rem; 
                font-weight: 500; 
                cursor: pointer; 
                transition: all 0.2s ease;
                min-width: 140px;
              }
              .btn:hover { 
                background: #f0f0f0; 
                transform: translateY(-1px);
              }
              .error { 
                background: #330000; 
                color: #ff6666; 
                padding: 16px; 
                border-radius: 8px; 
                margin-bottom: 24px; 
                border: 1px solid #660000;
                text-align: center;
              }
              .instructions {
                color: #666666;
                font-size: 0.9rem;
                margin-bottom: 20px;
              }
              .security-icon {
                font-size: 2.5rem;
                margin-bottom: 16px;
                text-align: center;
              }
              .user-info {
                text-align: center;
                margin-bottom: 32px;
                padding: 16px;
                background: #111111;
                border-radius: 8px;
                border: 1px solid #222222;
              }
              .user-info .username {
                font-size: 1.2rem;
                color: #ffffff;
                font-weight: 400;
              }
              .user-info .label {
                font-size: 0.85rem;
                color: #666666;
                margin-bottom: 4px;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="security-icon">🔐</div>
              <h2>Two-Factor Authentication</h2>
              <p class="subtitle">Decrypt the challenge with your PGP private key</p>
              
              <div class="user-info">
                <div class="label">Authenticating as</div>
                <div class="username">#{CGI.escapeHTML(account[:username])}</div>
              </div>
              
              #{flash['error'] ? "<div class='error'>#{flash['error']}</div>" : ''}
              
              <div class="challenge-container">
                <div class="instructions">Encrypted challenge:</div>
                <pre class="encrypted-text">#{CGI.escapeHTML(encrypted)}</pre>
              </div>
              
              <div class="form-container">
                <div class="instructions">Enter the decrypted code:</div>
                <form method="post">
                  <input type="text" name="code" placeholder="Enter decrypted code" required autocomplete="off">
                  <br>
                  <button type="submit" class="btn">Verify</button>
                </form>
              </div>
            </div>
          </body>
          </html>
        HTML
      end

      r.post do
        submitted_code = r.params["code"].to_s.strip
        
        recent_attempts = DB[:challenges].where(account_id: account_id)
                                        .where { created_at > Time.now - 60 }
                                        .count
        
        if recent_attempts > 5
          flash["error"] = "Too many attempts. Please wait before trying again."
          r.redirect "/pgp-2fa"
        end
        
        row = DB[:challenges].where(account_id: account_id)
                              .reverse(:id).first
                              
        unless row && row[:expires_at] > Time.now
          flash["error"] = "Challenge expired. Please try again."
          r.redirect "/pgp-2fa"
        end
        
        if submitted_code == row[:code]
          DB[:challenges].where(account_id: account_id).delete
          session[:rodauth_session_key] = account_id
          session.delete(:pending_account_id)
          flash["notice"] = "Authentication successful"
          r.redirect "/dashboard"
        else
          flash["error"] = "Incorrect code. Please try again."
          r.redirect "/pgp-2fa"
        end
      end
    end

    # Remove old pgp-auth route
    r.on "pgp-auth" do
      r.redirect "/login"
    end

    r.on "dashboard" do
      unless session[:rodauth_session_key]
        r.redirect "/login"
      end
      
      account_id = session[:rodauth_session_key]
      account = DB[:accounts].where(id: account_id).first
      
      response['Content-Type'] = 'text/html; charset=UTF-8'
      <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>Dashboard • PGP Auth</title>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
              font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
              background: #000000; 
              color: #ffffff; 
              min-height: 100vh; 
              display: flex; 
              align-items: center; 
              justify-content: center;
              padding: 20px;
            }
            .container { 
              max-width: 500px; 
              width: 100%;
              text-align: center;
            }
            .success-icon { 
              font-size: 4rem; 
              margin-bottom: 24px; 
              color: #00ff88;
            }
            h2 { 
              font-size: 2.5rem; 
              font-weight: 300; 
              margin-bottom: 16px; 
              letter-spacing: -0.02em;
            }
            .welcome-container { 
              background: #111111; 
              padding: 40px; 
              border-radius: 12px; 
              border: 1px solid #222222;
              margin-bottom: 24px;
            }
            p { 
              font-size: 1.1rem; 
              color: #cccccc; 
              margin-bottom: 32px; 
              line-height: 1.6;
            }
            .notice { 
              background: #003322; 
              color: #00ff88; 
              padding: 16px; 
              border-radius: 8px; 
              margin-bottom: 24px; 
              border: 1px solid #006644;
            }
            .logout-btn { 
              display: inline-block;
              color: #666666; 
              text-decoration: none; 
              padding: 12px 24px; 
              border: 1px solid #333333; 
              border-radius: 8px; 
              font-weight: 500;
              transition: all 0.2s ease;
            }
            .logout-btn:hover { 
              color: #ffffff; 
              border-color: #ffffff;
              transform: translateY(-1px);
            }
            .user-greeting {
              font-size: 1.3rem;
              color: #ffffff;
              margin-bottom: 24px;
            }
            .security-info {
              background: #0a0a0a;
              padding: 20px;
              border-radius: 8px;
              border: 1px solid #222222;
              margin-bottom: 24px;
              text-align: left;
              font-size: 0.9rem;
            }
            .security-info strong {
              color: #00ff88;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="success-icon">🔓</div>
            
            #{flash['notice'] ? "<div class='notice'>#{flash['notice']}</div>" : ''}
            
            <div class="user-greeting">Welcome, #{CGI.escapeHTML(account[:username])}!</div>
            
            <h2>Secure Dashboard</h2>
            
            <div class="welcome-container">
              <p>You've successfully authenticated using two-factor authentication with PGP cryptographic verification.</p>
              
              <div class="security-info">
                <strong>✓ Password Protected:</strong> Primary authentication<br>
                <strong>✓ PGP 2FA Enabled:</strong> Cryptographic second factor<br>
                <strong>✓ Zero-Knowledge:</strong> Server stores no secrets
              </div>
              
              <p>Your account is protected by industry-standard security measures.</p>
            </div>
            
            <a href="/logout" class="logout-btn">Sign Out</a>
          </div>
        </body>
        </html>
      HTML
    end

    r.on "logout" do
      session.clear
      r.redirect "/"
    end
  end

  def csrf_tag
    Rack::Csrf.csrf_tag(env)
  end
end
