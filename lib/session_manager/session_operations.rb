# frozen_string_literal: true

module SessionManager
  # Core session operations for creation and validation
  module SessionOperations
    DEFAULT_TIMEOUT_HOURS = 24
    MAX_CONCURRENT_SESSIONS = 5

    module_function

    # Create a new session
    def create_session(account_id, ip_address, user_agent)
      SessionManager.cleanup_expired_sessions

      account = DB[:accounts].where(id: account_id).first
      return nil unless account

      enforce_session_limit(account_id, account)

      token = SecureRandom.hex(32)
      timeout_hours = account[:session_timeout_hours] || DEFAULT_TIMEOUT_HOURS
      expires_at = Time.now + (timeout_hours * 3600)

      DB[:user_sessions].insert(
        account_id: account_id,
        session_token: token,
        ip_address: ip_address&.slice(0, 45),
        user_agent: user_agent&.slice(0, 1000),
        expires_at: expires_at
      )

      AuditLogger.log_event(account_id, 'login', ip_address, user_agent, {
                              session_token: "#{token[0..8]}...",
                              expires_at: expires_at
                            })

      token
    end

    # Validate and refresh a session
    def validate_session(session_token, ip_address, user_agent)
      return nil unless session_token

      session = DB[:user_sessions]
                .where(session_token: session_token, revoked: false)
                .where { expires_at > Time.now }
                .first

      return nil unless session

      DB[:user_sessions]
        .where(id: session[:id])
        .update(
          last_accessed_at: Time.now,
          ip_address: ip_address&.slice(0, 45),
          user_agent: user_agent&.slice(0, 1000)
        )

      session[:account_id]
    end

    private

    def enforce_session_limit(account_id, account)
      active_count = DB[:user_sessions]
                     .where(account_id: account_id, revoked: false)
                     .where { expires_at > Time.now }
                     .count

      max_sessions = account[:max_concurrent_sessions] || MAX_CONCURRENT_SESSIONS

      return unless active_count >= max_sessions

      oldest = DB[:user_sessions]
               .where(account_id: account_id, revoked: false)
               .where { expires_at > Time.now }
               .order(:last_accessed_at)
               .first

      revoke_session(oldest[:session_token], 'max_sessions_exceeded') if oldest
    end
  end
end
