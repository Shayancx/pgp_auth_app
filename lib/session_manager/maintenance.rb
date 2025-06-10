# frozen_string_literal: true

module SessionManager
  # Handles session maintenance and cleanup
  module Maintenance
    module_function

    # Get active sessions for an account
    def get_active_sessions(account_id)
      DB[:user_sessions]
        .where(account_id: account_id, revoked: false)
        .where { expires_at > Time.now }
        .order(:last_accessed_at.desc)
        .all
    end

    # Clean up expired sessions
    def cleanup_expired_sessions
      expired_count = DB[:user_sessions]
                      .where { expires_at < Time.now }
                      .update(revoked: true, revoked_at: Time.now)

      old_logs = DB[:audit_logs]
                 .where { created_at < Time.now - (90 * 24 * 3600) }
                 .delete

      { expired_sessions: expired_count, old_logs: old_logs }
    end

    # Get session fingerprint for display
    def session_fingerprint(session)
      browser = parse_user_agent(session[:user_agent])
      location = session[:ip_address]

      {
        browser: browser,
        location: location,
        created: session[:created_at],
        last_accessed: session[:last_accessed_at],
        expires: session[:expires_at]
      }
    end

    private

    def parse_user_agent(user_agent)
      return 'Unknown' unless user_agent

      case user_agent
      when /Chrome/i then 'Chrome'
      when /Firefox/i then 'Firefox'
      when /Safari/i then 'Safari'
      when /Edge/i then 'Edge'
      else 'Other Browser'
      end
    end
  end
end
