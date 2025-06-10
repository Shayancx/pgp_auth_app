# frozen_string_literal: true

# Routes for authenticated dashboard pages
module Routes
  # Dashboard and account management routes
  module Dashboard
    def self.registered(app)
      app.instance_eval do
        # Main dashboard
        r.on 'dashboard' do
          require_authentication(r) do |account|
            @account = account
            view 'dashboard'
          end
        end

        # Session Management
        r.on 'sessions' do
          require_authentication(r) do |account|
            @account = account

            r.get do
              @sessions = SessionManager.get_active_sessions(account[:id])
              @current_token = session[:session_token]
              view 'sessions'
            end

            r.post 'revoke' do
              token = r.params['token']
              if token && token != session[:session_token]
                SessionManager.revoke_session(token, 'user_revoked')
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

        # Security Dashboard
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
      end
    end

    def self.require_authentication(r)
      r.redirect '/login' unless r.session[:rodauth_session_key]

      account_id = r.session[:rodauth_session_key]
      account = DB[:accounts].where(id: account_id).first

      unless account
        clear_session_and_logout
        r.redirect '/login'
      end

      yield account
    end
  end
end
