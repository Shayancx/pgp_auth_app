# frozen_string_literal: true

require_relative '../config/database'
require 'securerandom'
require 'json'
require 'digest'

# Main module for session management functionality
module SessionManager
  DEFAULT_TIMEOUT_HOURS = 24
  MAX_CONCURRENT_SESSIONS = 5
  SESSION_TOKEN_LENGTH = 32

  class << self
    # Create a new session
    def create_session(account_id, ip_address, user_agent)
      cleanup_expired_sessions

      account = DB[:accounts].where(id: account_id).first
      return nil unless account

      enforce_session_limit(account_id, account)

      token = SecureRandom.hex(SESSION_TOKEN_LENGTH)
      token_hash = hash_token(token)
      timeout_hours = account[:session_timeout_hours] || DEFAULT_TIMEOUT_HOURS
      expires_at = Time.now + (timeout_hours * 3600)

      DB[:user_sessions].insert(
        account_id: account_id,
        session_token: token_hash,
        ip_address: ip_address&.slice(0, 45),
        user_agent: user_agent&.slice(0, 1000),
        expires_at: expires_at,
        created_at: Time.now,
        last_accessed_at: Time.now
      )

      log_event(account_id, 'login', ip_address, user_agent, {
                  session_token: "#{token_hash[0..8]}...",
                  expires_at: expires_at
                })

      token
    end

    # Validate and refresh a session
    def validate_session(session_token, ip_address, user_agent)
      return nil unless session_token
      return nil unless session_token.length == SESSION_TOKEN_LENGTH * 2

      token_hash = hash_token(session_token)
      session = DB[:user_sessions]
                .where(session_token: token_hash, revoked: false)
                .where { expires_at > Time.now }
                .first

      return nil unless session

      # Update session activity
      DB[:user_sessions]
        .where(id: session[:id])
        .update(
          last_accessed_at: Time.now,
          ip_address: ip_address&.slice(0, 45),
          user_agent: user_agent&.slice(0, 1000)
        )

      # Log if IP changed
      if session[:ip_address] != ip_address
        log_event(session[:account_id], 'session_ip_changed', ip_address, user_agent, {
                    old_ip: session[:ip_address],
                    new_ip: ip_address
                  })
      end

      session[:account_id]
    end

    # Revoke a specific session by token
    def revoke_session(session_token, reason = 'user_logout')
      return false unless session_token
      return false unless session_token.length == SESSION_TOKEN_LENGTH * 2

      token_hash = hash_token(session_token)
      session = DB[:user_sessions].where(session_token: token_hash).first
      return false unless session

      DB[:user_sessions]
        .where(id: session[:id])
        .update(revoked: true, revoked_at: Time.now)

      log_event(session[:account_id], 'session_revoked', nil, nil, {
                  reason: reason,
                  session_token: "#{token_hash[0..8]}..."
                })

      true
    end

    # Revoke by token hash (internal use)
    def revoke_session_by_hash(token_hash, reason = 'system')
      session = DB[:user_sessions].where(session_token: token_hash).first
      return false unless session

      DB[:user_sessions]
        .where(id: session[:id])
        .update(revoked: true, revoked_at: Time.now)

      log_event(session[:account_id], 'session_revoked', nil, nil, {
                  reason: reason,
                  session_token: "#{token_hash[0..8]}..."
                })

      true
    end

    # Revoke all sessions for an account
    def revoke_all_sessions(account_id, except_token = nil)
      query = DB[:user_sessions].where(account_id: account_id, revoked: false)

      if except_token && except_token.length == SESSION_TOKEN_LENGTH * 2
        except_token_hash = hash_token(except_token)
        query = query.exclude(session_token: except_token_hash)
      end

      count = query.update(revoked: true, revoked_at: Time.now)

      log_event(account_id, 'all_sessions_revoked', nil, nil, {
                  revoked_count: count,
                  except_token: except_token ? "#{hash_token(except_token)[0..8]}..." : nil
                })

      count
    end

    # Get active sessions for an account
    def get_active_sessions(account_id)
      DB[:user_sessions]
        .where(account_id: account_id, revoked: false)
        .where { expires_at > Time.now }
        .reverse(:last_accessed_at)
        .all
    end

    # Token matches session check for UI
    def token_matches_session?(session_token, stored_hash)
      return false unless session_token && stored_hash
      return false unless session_token.length == SESSION_TOKEN_LENGTH * 2

      hash_token(session_token) == stored_hash
    end

    # Clean up expired sessions
    def cleanup_expired_sessions
      expired_count = DB[:user_sessions]
                      .where { expires_at < Time.now }
                      .where(revoked: false)
                      .update(revoked: true, revoked_at: Time.now)

      # Keep audit logs for 90 days
      old_logs = 0
      if DB.table_exists?(:audit_logs)
        old_logs = DB[:audit_logs]
                   .where { created_at < Time.now - (90 * 24 * 3600) }
                   .delete
      end

      { expired_sessions: expired_count, old_logs: old_logs }
    end

    # Log audit event
    def log_event(account_id, event_type, ip_address, user_agent, details = {})
      return unless DB.table_exists?(:audit_logs)

      DB[:audit_logs].insert(
        account_id: account_id,
        event_type: event_type,
        ip_address: ip_address&.slice(0, 45),
        user_agent: user_agent&.slice(0, 1000),
        details: details.to_json,
        created_at: Time.now
      )
    end

    # Get audit log for account
    def get_audit_log(account_id, limit = 50)
      return [] unless DB.table_exists?(:audit_logs)

      DB[:audit_logs]
        .where(account_id: account_id)
        .reverse(:created_at)
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

    def hash_token(token)
      Digest::SHA256.hexdigest(token)
    end

    def enforce_session_limit(account_id, account)
      active_count = DB[:user_sessions]
                     .where(account_id: account_id, revoked: false)
                     .where { expires_at > Time.now }
                     .count

      max_sessions = account[:max_concurrent_sessions] || MAX_CONCURRENT_SESSIONS

      return unless active_count >= max_sessions

      # Revoke oldest session
      oldest = DB[:user_sessions]
               .where(account_id: account_id, revoked: false)
               .where { expires_at > Time.now }
               .order(:last_accessed_at)
               .first

      revoke_session_by_hash(oldest[:session_token], 'max_sessions_exceeded') if oldest
    end

    def parse_user_agent(user_agent)
      return 'Unknown' unless user_agent

      case user_agent
      when %r{Chrome/(\d+)}i then "Chrome #{::Regexp.last_match(1)}"
      when %r{Firefox/(\d+)}i then "Firefox #{::Regexp.last_match(1)}"
      when %r{Safari/(\d+)}i then 'Safari'
      when %r{Edge/(\d+)}i then "Edge #{::Regexp.last_match(1)}"
      else 'Other Browser'
      end
    end
  end
end
