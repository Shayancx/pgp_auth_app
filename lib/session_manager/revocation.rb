# frozen_string_literal: true

module SessionManager
  # Handles session revocation operations
  module Revocation
    module_function

    # Revoke a specific session
    def revoke_session(session_token, reason = 'user_logout')
      session = DB[:user_sessions].where(session_token: session_token).first
      return false unless session

      DB[:user_sessions]
        .where(id: session[:id])
        .update(revoked: true, revoked_at: Time.now)

      AuditLogger.log_event(session[:account_id], 'session_revoked', nil, nil, {
                              reason: reason,
                              session_token: "#{session_token[0..8]}..."
                            })

      true
    end

    # Revoke all sessions for an account
    def revoke_all_sessions(account_id, except_token = nil)
      query = DB[:user_sessions].where(account_id: account_id, revoked: false)
      query = query.exclude(session_token: except_token) if except_token

      count = query.update(revoked: true, revoked_at: Time.now)

      AuditLogger.log_event(account_id, 'all_sessions_revoked', nil, nil, {
                              revoked_count: count,
                              except_token: except_token ? "#{except_token[0..8]}..." : nil
                            })

      count
    end
  end
end
