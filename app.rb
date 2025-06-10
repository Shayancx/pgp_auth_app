# frozen_string_literal: true
require "roda"
require "cgi"
require "tilt/erb"
require_relative "config/database"
require "rodauth"
require_relative "lib/pgp_auth"
require_relative "pgp_challenge_feature"
require "bcrypt"

class App < Roda
  plugin :flash
  plugin :render, engine: "erb", views: "views"
  plugin :public
  plugin :default_headers, 
    'Content-Type'=>'text/html; charset=UTF-8'

  plugin :rodauth do
    enable :base, :pgp_challenge
    # Remove logout feature from Rodauth
  end

  route do |r|
    r.rodauth

    r.root do
      view "home"
    end

    # Handle logout manually to avoid CSRF conflicts
    r.on "logout" do
      r.get do
        view "logout"
      end
      
      r.post do
        session.clear
        flash["notice"] = "You have been logged out"
        r.redirect "/"
      end
    end

    r.on "login" do
      r.get do
        view "login"
      end

      r.post do
        username = r.params["username"].to_s.strip
        password = r.params["password"].to_s
        
        account = DB[:accounts].where(username: username, verified: true).first
        
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
        view "register"
      end

      r.post do
        username = r.params["username"].to_s.strip
        password = r.params["password"].to_s
        key_text = r.params["public_key"].to_s.strip
        
        if username.empty? || password.empty? || key_text.empty?
          flash["error"] = "All fields are required"
          r.redirect "/register"
        end
        
        # Check if username already exists
        if DB[:accounts].where(username: username).count > 0
          flash["error"] = "Username already taken"
          r.redirect "/register"
        end
        
        begin
          fp = PgpAuth.import_and_fingerprint(key_text)
          password_hash = BCrypt::Password.create(password)
          
          # Create unverified account
          id = DB[:accounts].insert(
            username: username,
            password_hash: password_hash,
            public_key: key_text, 
            fingerprint: fp,
            verified: false
          )
          
          # Store the account ID for verification
          session[:unverified_account_id] = id
          r.redirect "/verify-pgp"
        rescue => e
          flash["error"] = "Invalid PGP key: #{e.message}"
          r.redirect "/register"
        end
      end
    end

    r.on "verify-pgp" do
      account_id = session[:unverified_account_id]
      unless account_id
        flash["error"] = "No pending registration found"
        r.redirect "/register"
      end
      
      @account = DB[:accounts].where(id: account_id).first
      unless @account
        flash["error"] = "Account not found"
        r.redirect "/register"
      end

      r.get do
        # Generate verification challenge
        code = PgpAuth.random_code
        DB[:accounts].where(id: account_id).update(
          verification_code: code,
          verification_expires_at: Time.now + 600 # 10 minutes
        )
        @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)
        
        view "verify_pgp"
      end

      r.post do
        submitted_code = r.params["code"].to_s.strip
        
        # Reload account to get latest verification code
        account = DB[:accounts].where(id: account_id).first
        
        unless account[:verification_expires_at] && account[:verification_expires_at] > Time.now
          flash["error"] = "Verification expired. Please try again."
          r.redirect "/verify-pgp"
        end
        
        if submitted_code == account[:verification_code]
          # Mark account as verified
          DB[:accounts].where(id: account_id).update(
            verified: true,
            verification_code: nil,
            verification_expires_at: nil
          )
          
          # Log the user in
          session[:rodauth_session_key] = account_id
          session.delete(:unverified_account_id)
          flash["notice"] = "Account created and verified successfully!"
          r.redirect "/dashboard"
        else
          flash["error"] = "Incorrect code. Please try again."
          r.redirect "/verify-pgp"
        end
      end
    end

    r.on "pgp-2fa" do
      account_id = session[:pending_account_id]
      r.redirect "/login" unless account_id
      
      @account = DB[:accounts].where(id: account_id).first
      r.redirect "/login" unless @account

      r.get do
        # Clean up expired challenges
        DB[:challenges].where(account_id: account_id)
                       .where { expires_at < Time.now }
                       .delete
        
        code = PgpAuth.random_code
        DB[:challenges].insert(account_id: account_id,
                               code: code,
                               expires_at: Time.now + 300)
        @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)
        
        view "pgp_2fa"
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

    r.on "dashboard" do
      unless session[:rodauth_session_key]
        r.redirect "/login"
      end
      
      account_id = session[:rodauth_session_key]
      @account = DB[:accounts].where(id: account_id).first
      
      unless @account
        session.clear
        r.redirect "/login"
      end
      
      view "dashboard"
    end
  end

  def csrf_tag
    Rack::Csrf.csrf_tag(env)
  end
end
