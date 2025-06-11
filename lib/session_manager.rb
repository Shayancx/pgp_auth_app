# frozen_string_literal: true

require_relative '../config/database'
require 'securerandom'
require 'json'
require 'digest'
require 'openssl'

# SECURITY HARDENED: Enhanced session management with military-grade security
module SessionManager
  DEFAULT_TIMEOUT_HOURS = 24
  MAX_CONCURRENT_SESSIONS = 3  # Reduced for security
  SESSION_TOKEN_LENGTH = 32
  SESSION_REGENERATION_INTERVAL = 1800 # 30 minutes (reduced)

  # SECURITY HARDENED: Enhanced session security
  SESSION_SALT = ENV.fetch('SESSION_SALT', SecureRandom.hex(64))
  
  class << self
    # SECURITY HARDENED: Enhanced session creation with security checks
    def create_session(account_id, ip_address, user_agent)
      cleanup_expired_sessions

      account = DB[:accounts].where(id: account_id).first
      return nil unless account

      validate_account_for_session(account)
      enforce_session_limit(account_id, account)

      # SECURITY HARDENED: Generate cryptographically secure token
      token = generate_secure_session_token
      token_hash = hash_session_token(token)
      
      timeout_hours = [account[:session_timeout_hours] || DEFAULT_TIMEOUT_HOURS, 24].min # Cap timeout
      expires_at = Time.now + (timeout_hours * 3600)

      session_data = {
        account_id: account_id,
        session_token: token_hash,
        ip_address: sanitize_ip(ip_address),
        user_agent: sanitize_user_agent(user_agent),
        expires_at: expires_at,
        created_at: Time.now,
        last_accessed_at: Time.now,
        security_level: calculate_security_level(ip_address, user_agent),
        device_fingerprint: generate_device_fingerprint(ip_address, user_agent),
        access_count: 0,
        last_regenerated_at: Time.now
      }

      session_id = DB[:user_sessions].insert(session_data)

      log_event(account_id, 'session_created', ip_address, user_agent, {
        session_id: session_id,
        session_token: "#{token_hash[0..8]}...",
        expires_at: expires_at,
        security_level: session_data[:security_level],
        success: true
      })

      token
    end

    # SECURITY HARDENED: Enhanced session validation with strict security
    def validate_session(session_token, ip_address, user_agent)
      return nil unless session_token
      return nil unless session_token.length == SESSION_TOKEN_LENGTH * 2
      return nil unless session_token.match?(/\A[a-f0-9]{#{SESSION_TOKEN_LENGTH * 2}}\z/)

      token_hash = hash_session_token(session_token)
      session = DB[:user_sessions]
                .where(session_token: token_hash, revoked: false)
                .where { expires_at > Time.now }
                .first

      return nil unless session

      # SECURITY HARDENED: Enhanced security validations
      unless validate_session_security(session, ip_address, user_agent)
        revoke_session_by_hash(token_hash, 'security_violation')
        return nil
      end

      update_session_activity(session, ip_address, user_agent)
      session[:account_id]
    end

    # Enhanced session revocation
    def revoke_session(session_token, reason = 'user_logout')
      return false unless session_token
      return false unless session_token.length == SESSION_TOKEN_LENGTH * 2

      token_hash = hash_session_token(session_token)
      session = DB[:user_sessions].where(session_token: token_hash).first
      return false unless session

      DB[:user_sessions]
        .where(id: session[:id])
        .update(
          revoked: true, 
          revoked_at: Time.now,
          revocation_reason: reason
        )

      log_event(session[:account_id], 'session_revoked', nil, nil, {
        reason: reason,
        session_id: session[:id],
        session_token: "#{token_hash[0..8]}...",
        success: true
      })

      true
    end

    def revoke_session_by_hash(token_hash, reason = 'system')
      session = DB[:user_sessions].where(session_token: token_hash).first
      return false unless session

      DB[:user_sessions]
        .where(id: session[:id])
        .update(
          revoked: true, 
          revoked_at: Time.now,
          revocation_reason: reason
        )

      log_event(session[:account_id], 'session_revoked', nil, nil, {
        reason: reason,
        session_id: session[:id],
        session_token: "#{token_hash[0..8]}...",
        success: true
      })

      true
    end

    def revoke_all_sessions(account_id, except_token = nil)
      query = DB[:user_sessions].where(account_id: account_id, revoked: false)

      if except_token && except_token.length == SESSION_TOKEN_LENGTH * 2
        except_token_hash = hash_session_token(except_token)
        query = query.exclude(session_token: except_token_hash)
      end

      sessions_to_revoke = query.all
      count = query.update(
        revoked: true, 
        revoked_at: Time.now,
        revocation_reason: 'bulk_revocation'
      )

      sessions_to_revoke.each do |session|
        log_event(account_id, 'session_revoked', nil, nil, {
          reason: 'bulk_revocation',
          session_id: session[:id],
          session_token: "#{session[:session_token][0..8]}...",
          success: true
        })
      end

      log_event(account_id, 'all_sessions_revoked', nil, nil, {
        revoked_count: count,
        except_token: except_token ? "#{hash_session_token(except_token)[0..8]}..." : nil,
        success: true
      })

      count
    end

    def get_active_sessions(account_id)
      DB[:user_sessions]
        .where(account_id: account_id, revoked: false)
        .where { expires_at > Time.now }
        .reverse(:last_accessed_at)
        .all
        .map { |session| enhance_session_info(session) }
    end

    def token_matches_session?(session_token, stored_hash)
      return false unless session_token && stored_hash
      return false unless session_token.length == SESSION_TOKEN_LENGTH * 2

      calculated_hash = hash_session_token(session_token)
      
      if defined?(OpenSSL.secure_compare)
        OpenSSL.secure_compare(calculated_hash, stored_hash)
      else
        calculated_hash == stored_hash
      end
    end

    def cleanup_expired_sessions
      expired_count = DB[:user_sessions]
                      .where { expires_at < Time.now }
                      .where(revoked: false)
                      .update(
                        revoked: true, 
                        revoked_at: Time.now,
                        revocation_reason: 'expired'
                      )

      old_logs = 0
      if DB.table_exists?(:audit_logs)
        retention_days = ENV.fetch('AUDIT_LOG_RETENTION_DAYS', '30').to_i # Reduced retention
        cutoff_date = Time.now - (retention_days * 24 * 3600)
        
        old_logs = DB[:audit_logs]
                   .where { created_at < cutoff_date }
                   .delete
      end

      if expired_count > 0 || old_logs > 0
        log_event(nil, 'session_cleanup', nil, nil, {
          expired_sessions: expired_count,
          old_audit_logs: old_logs
        })
      end

      { expired_sessions: expired_count, old_logs: old_logs }
    end

    def log_event(account_id, event_type, ip_address, user_agent, details = {})
      return unless DB.table_exists?(:audit_logs)

      # SECURITY HARDENED: Sanitize details and add security context
      sanitized_details = sanitize_audit_details(details)
      
      sanitized_details[:timestamp] = Time.now.to_i
      sanitized_details[:security_context] = {
        ip_hash: ip_address ? Digest::SHA256.hexdigest("#{SESSION_SALT}:#{ip_address}")[0..7] : nil,
        user_agent_hash: user_agent ? Digest::SHA256.hexdigest("#{SESSION_SALT}:#{user_agent}")[0..7] : nil
      }

      # SECURITY HARDENED: Limit audit log details
      sanitized_details = sanitized_details.to_json[0..2000] # Limit size

      DB[:audit_logs].insert(
        account_id: account_id,
        event_type: event_type,
        ip_address: sanitize_ip(ip_address),
        user_agent: sanitize_user_agent(user_agent),
        details: sanitized_details,
        success: details.fetch(:success, true),
        created_at: Time.now
      )
    end

    def get_audit_log(account_id, limit = 25) # Reduced limit
      return [] unless DB.table_exists?(:audit_logs)

      logs = DB[:audit_logs]
             .where(account_id: account_id)
             .reverse(:created_at)
             .limit(limit)
             .all

      logs.map do |log|
        log[:details] = parse_audit_details(log[:details])
        log
      end
    end

    def session_fingerprint(session)
      browser = parse_user_agent(session[:user_agent])
      location = anonymize_ip(session[:ip_address])

      {
        browser: browser,
        location: location,
        created: session[:created_at],
        last_accessed: session[:last_accessed_at],
        expires: session[:expires_at],
        security_level: session[:security_level] || 'unknown',
        device_fingerprint: session[:device_fingerprint]
      }
    end

    private

    # SECURITY HARDENED: Generate cryptographically secure session token
    def generate_secure_session_token
      # Use only high-entropy sources
      primary_entropy = SecureRandom.random_bytes(64)
      additional_entropy = SecureRandom.random_bytes(32)
      
      # Combine and hash to get token
      combined = primary_entropy + additional_entropy
      Digest::SHA256.hexdigest(combined)[0, SESSION_TOKEN_LENGTH * 2]
    end

    # SECURITY HARDENED: Enhanced session token hashing
    def hash_session_token(token)
      iterations = 10000 # Increased iterations
      key_length = 32
      
      derived_key = OpenSSL::PKCS5.pbkdf2_hmac(
        token,
        SESSION_SALT,
        iterations,
        key_length,
        OpenSSL::Digest.new('SHA256')
      )
      
      derived_key.unpack1('H*')
    end

    def validate_account_for_session(account)
      raise 'Account not verified' unless account[:verified]
      raise 'Account disabled' if account[:disabled]
      
      if account[:failed_login_count] && account[:failed_login_count] > 50
        raise 'Account locked due to suspicious activity'
      end
    end

    # SECURITY HARDENED: Enhanced session security validation
    def validate_session_security(session, ip_address, user_agent)
      # Strict IP validation
      if session[:ip_address] && ip_address
        unless ip_addresses_compatible?(session[:ip_address], ip_address)
          log_event(session[:account_id], 'session_ip_changed', ip_address, user_agent, {
            original_ip: anonymize_ip(session[:ip_address]),
            new_ip: anonymize_ip(ip_address),
            success: false
          })
          return false # Fail on IP change
        end
      end

      # Check session age
      if session_needs_regeneration?(session)
        log_event(session[:account_id], 'session_regeneration_needed', ip_address, user_agent, {
          session_age: Time.now - session[:created_at],
          success: true
        })
      end

      # Check for suspicious activity patterns
      if session[:access_count] && session[:access_count] > 1000
        return false # Too many accesses
      end

      true
    end

    def update_session_activity(session, ip_address, user_agent)
      updates = {
        last_accessed_at: Time.now,
        access_count: (session[:access_count] || 0) + 1
      }

      # Update IP if changed (with logging)
      if ip_address && session[:ip_address] != ip_address
        updates[:ip_address] = sanitize_ip(ip_address)
        
        log_event(session[:account_id], 'session_ip_updated', ip_address, user_agent, {
          old_ip: anonymize_ip(session[:ip_address]),
          new_ip: anonymize_ip(ip_address),
          success: true
        })
      end

      DB[:user_sessions].where(id: session[:id]).update(updates)
    end

    def calculate_security_level(ip_address, user_agent)
      score = 0
      
      if ip_address
        score += 1 if ip_address.match?(/^192\.168\./)
        score += 1 if ip_address.match?(/^10\./)
        score -= 1 unless ip_address.match?(/^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/)
      end
      
      if user_agent
        score += 1 if user_agent.include?('Chrome') || user_agent.include?('Firefox')
        score -= 2 if user_agent.include?('curl') || user_agent.include?('wget')
      end

      case score
      when 2..Float::INFINITY then 'high'
      when 0..1 then 'medium'
      else 'low'
      end
    end

    def generate_device_fingerprint(ip_address, user_agent)
      components = [
        ip_address&.split('.')&.first(3)&.join('.'),
        parse_user_agent(user_agent),
        SecureRandom.hex(4) # Add randomness
      ].compact.join(':')
      
      Digest::SHA256.hexdigest("#{SESSION_SALT}:#{components}")[0..15]
    end

    def session_needs_regeneration?(session)
      return true unless session[:last_regenerated_at]
      
      (Time.now - session[:last_regenerated_at]) > SESSION_REGENERATION_INTERVAL
    end

    def enforce_session_limit(account_id, account)
      active_sessions = DB[:user_sessions]
                       .where(account_id: account_id, revoked: false)
                       .where { expires_at > Time.now }
                       .all

      max_sessions = [account[:max_concurrent_sessions] || MAX_CONCURRENT_SESSIONS, MAX_CONCURRENT_SESSIONS].min

      if active_sessions.length >= max_sessions
        sessions_to_revoke = active_sessions
                            .sort_by { |s| s[:last_accessed_at] }
                            .first(active_sessions.length - max_sessions + 1)

        sessions_to_revoke.each do |session|
          revoke_session_by_hash(session[:session_token], 'max_sessions_exceeded')
        end
      end
    end

    def parse_user_agent(user_agent)
      return 'Unknown' unless user_agent

      case user_agent
      when /Chrome\/(\d+)/i then "Chrome #{$1}"
      when /Firefox\/(\d+)/i then "Firefox #{$1}"
      when /Safari\/(\d+)/i then 'Safari'
      when /Edge\/(\d+)/i then "Edge #{$1}"
      else 'Other'
      end
    end

    def sanitize_ip(ip_address)
      return nil unless ip_address
      ip_address.to_s.strip.slice(0, 45)
    end

    def sanitize_user_agent(user_agent)
      return nil unless user_agent
      user_agent.to_s.strip.gsub(/[^\x20-\x7E]/, '').slice(0, 200) # Reduced size
    end

    def anonymize_ip(ip_address)
      return 'unknown' unless ip_address
      
      parts = ip_address.split('.')
      if parts.length == 4
        "#{parts[0]}.#{parts[1]}.xxx.xxx" # More anonymization
      else
        'anonymized'
      end
    end

    def ip_addresses_compatible?(ip1, ip2)
      return true if ip1 == ip2
      
      # SECURITY HARDENED: Stricter IP validation - only allow exact match
      false
    end

    def sanitize_audit_details(details)
      sanitized = {}
      
      details.each do |key, value|
        case value
        when String
          sanitized[key] = value.slice(0, 500) # Reduced size
        when Numeric, TrueClass, FalseClass, NilClass
          sanitized[key] = value
        when Hash
          sanitized[key] = sanitize_audit_details(value)
        else
          sanitized[key] = value.to_s.slice(0, 500)
        end
      end
      
      sanitized
    end

    def parse_audit_details(details_json)
      return {} unless details_json
      
      JSON.parse(details_json)
    rescue JSON::ParserError
      { error: 'Invalid audit data' }
    end

    def enhance_session_info(session)
      session[:fingerprint] = session_fingerprint(session)
      session
    end
  end
end
