# frozen_string_literal: true

require_relative '../config/database'
require 'securerandom'
require 'json'

module SessionManager
  DEFAULT_TIMEOUT_HOURS = 24
  MAX_CONCURRENT_SESSIONS = 5

  module_function

  # Create a new session
  def create_session(account_id, ip_address, user_agent)
    cleanup_expired_sessions

    account = DB[:accounts].where(id: account_id).first
    return nil unless account

    # Limit concurrent sessions
    active_count = DB[:user_sessions]
                   .where(account_id: account_id, revoked: false)
                   .where { expires_at > Time.now }
                   .count

    max_sessions = account[:max_concurrent_sessions] || MAX_CONCURRENT_SESSIONS

    if active_count >= max_sessions
      # Revoke oldest session
      oldest = DB[:user_sessions]
               .where(account_id: account_id, revoked: false)
               .where { expires_at > Time.now }
               .order(:last_accessed_at)
               .first

      revoke_session(oldest[:session_token], 'max_sessions_exceeded') if oldest
    end

    # Create new session
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

    log_event(account_id, 'login', ip_address, user_agent, {
                session_token: "#{token[0..8]}...", # Partial token for audit
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

    # Update last accessed time
    DB[:user_sessions]
      .where(id: session[:id])
      .update(
        last_accessed_at: Time.now,
        ip_address: ip_address&.slice(0, 45),
        user_agent: user_agent&.slice(0, 1000)
      )

    session[:account_id]
  end

  # Revoke a specific session
  def revoke_session(session_token, reason = 'user_logout')
    session = DB[:user_sessions].where(session_token: session_token).first
    return false unless session

    DB[:user_sessions]
      .where(id: session[:id])
      .update(revoked: true, revoked_at: Time.now)

    log_event(session[:account_id], 'session_revoked', nil, nil, {
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

    log_event(account_id, 'all_sessions_revoked', nil, nil, {
                revoked_count: count,
                except_token: except_token ? "#{except_token[0..8]}..." : nil
              })

    count
  end

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

    # Also clean up old audit logs (keep 90 days)
    old_logs = DB[:audit_logs]
               .where { created_at < Time.now - (90 * 24 * 3600) }
               .delete

    { expired_sessions: expired_count, old_logs: old_logs }
  end

  # Log audit event
  def log_event(account_id, event_type, ip_address, user_agent, details = {})
    DB[:audit_logs].insert(
      account_id: account_id,
      event_type: event_type,
      ip_address: ip_address&.slice(0, 45),
      user_agent: user_agent&.slice(0, 1000),
      details: details.to_json
    )
  end

  # Get audit log for account
  def get_audit_log(account_id, limit = 50)
    DB[:audit_logs]
      .where(account_id: account_id)
      .order(:created_at.desc)
      .limit(limit)
      .all
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
    when /Chrome/i
      'Chrome'
    when /Firefox/i
      'Firefox'
    when /Safari/i
      'Safari'
    when /Edge/i
      'Edge'
    else
      'Other Browser'
    end
  end
end
