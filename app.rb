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
            }
            .btn:hover { 
              background: transparent; 
              color: #ffffff; 
              transform: translateY(-1px);
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
            <p>Secure, password-free authentication using cryptographic keys</p>
            <a href="/register" class="btn">Continue</a>
          </div>
        </body>
        </html>
      HTML
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
              textarea { 
                width: 100%; 
                padding: 20px; 
                border: 1px solid #333333; 
                border-radius: 8px; 
                font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; 
                background: #000000; 
                color: #ffffff; 
                font-size: 14px; 
                min-height: 280px; 
                resize: vertical;
                line-height: 1.4;
              }
              textarea:focus { 
                border-color: #ffffff; 
                outline: none; 
                box-shadow: 0 0 0 1px #ffffff;
              }
              textarea::placeholder {
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
                margin-top: 24px; 
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
            </style>
          </head>
          <body>
            <div class="container">
              <h2>Import PGP Key</h2>
              <p class="subtitle">Paste your ASCII-armored public key</p>
              #{flash['error'] ? "<div class='error'>#{flash['error']}</div>" : ''}
              <div class="form-container">
                <form method="post">
                  #{csrf_tag}
                  <textarea name="public_key" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF...
...
-----END PGP PUBLIC KEY BLOCK-----" required></textarea>
                  <button type="submit" class="btn">Import Key</button>
                </form>
              </div>
              <a href="/" class="back-link">← Back</a>
            </div>
          </body>
          </html>
        HTML
      end

      r.post do
        key_text = r.params["public_key"].to_s.strip
        halt(400, "Public key required") if key_text.empty?
        
        begin
          fp = PgpAuth.import_and_fingerprint(key_text)
          id = DB[:accounts].insert(public_key: key_text, fingerprint: fp)
          session[:account_id] = id
          r.redirect "/pgp-auth"
        rescue => e
          flash["error"] = "Invalid PGP key: #{e.message}"
          r.redirect "/register"
        end
      end
    end

    r.on "pgp-auth" do
      account_id = session[:account_id]
      r.redirect "/" unless account_id
      
      account = DB[:accounts].where(id: account_id).first
      r.redirect "/" unless account

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
            <title>Challenge • PGP Auth</title>
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
              .step-indicator {
                text-align: center;
                margin-bottom: 32px;
              }
              .step {
                display: inline-block;
                width: 32px;
                height: 32px;
                border-radius: 50%;
                background: #333333;
                color: #ffffff;
                line-height: 32px;
                margin: 0 8px;
                font-weight: 500;
              }
              .step.active {
                background: #ffffff;
                color: #000000;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="step-indicator">
                <span class="step">1</span>
                <span class="step active">2</span>
                <span class="step">3</span>
              </div>
              
              <h2>Decrypt Challenge</h2>
              <p class="subtitle">Use your private key to decrypt the message</p>
              
              #{flash['error'] ? "<div class='error'>#{flash['error']}</div>" : ''}
              
              <div class="challenge-container">
                <div class="instructions">Encrypted message:</div>
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
          r.redirect "/pgp-auth"
        end
        
        row = DB[:challenges].where(account_id: account_id)
                              .reverse(:id).first
                              
        unless row && row[:expires_at] > Time.now
          flash["error"] = "Challenge expired. Please try again."
          r.redirect "/pgp-auth"
        end
        
        if submitted_code == row[:code]
          DB[:challenges].where(account_id: account_id).delete
          session[:rodauth_session_key] = account_id
          session.delete(:account_id)
          flash["notice"] = "Authentication successful"
          r.redirect "/dashboard"
        else
          flash["error"] = "Incorrect code. Please try again."
          r.redirect "/pgp-auth"
        end
      end
    end

    r.on "dashboard" do
      unless session[:rodauth_session_key]
        r.redirect "/"
      end
      
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
            .step-indicator {
              margin-bottom: 32px;
            }
            .step {
              display: inline-block;
              width: 32px;
              height: 32px;
              border-radius: 50%;
              background: #00ff88;
              color: #000000;
              line-height: 32px;
              margin: 0 8px;
              font-weight: 500;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="step-indicator">
              <span class="step">✓</span>
              <span class="step">✓</span>
              <span class="step">✓</span>
            </div>
            
            <div class="success-icon">🔓</div>
            <h2>Authenticated</h2>
            
            #{flash['notice'] ? "<div class='notice'>#{flash['notice']}</div>" : ''}
            
            <div class="welcome-container">
              <p>Welcome to your secure dashboard. You've successfully authenticated using PGP cryptographic verification.</p>
              <p>No passwords. No vulnerabilities. Just pure cryptographic security.</p>
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
