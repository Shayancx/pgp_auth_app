# frozen_string_literal: true

require_relative '../config/database'
require 'securerandom'
require 'json'
require 'digest'
require 'openssl'

# Enhanced session management with comprehensive security
module SessionManager
  DEFAULT_TIMEOUT_HOURS = 24
  MAX_CONCURRENT_SESSIONS = 5
  SESSION_TOKEN_LENGTH = 32
  SESSION_REGENERATION_INTERVAL = 3600 # 1 hour

  # Enhanced session security
  SESSION_SALT = ENV.fetch('SESSION_SALT', 'default_session_salt_change_in_production')
  
  class << self
    # Enhanced session creation with security checks
    def create_session(account_id, ip_address, user_agent)
      cleanup_expired_sessions

      account = DB[:accounts].where(id: account_id).first
      return nil unless account

      # Validate account status
      validate_account_for_session(account)

      # Enforce session limits
      enforce_session_limit(account_id, account)

      # Generate cryptographically secure token
      token = generate_secure_session_token
      token_hash = hash_session_token(token)
      
      timeout_hours = account[:session_timeout_hours] || DEFAULT_TIMEOUT_HOURS
      expires_at = Time.now + (timeout_hours * 3600)

      # Enhanced session data
      session_data = {
        account_id: account_id,
        session_token: token_hash,
        ip_address: sanitize_ip(ip_address),
        user_agent: sanitize_user_agent(user_agent),
        expires_at: expires_at,
        created_at: Time.now,
        last_accessed_at: Time.now,
        security_level: calculate_security_level(ip_address, user_agent),
        device_fingerprint: generate_device_fingerprint(ip_address, user_agent)
      }

      session_id = DB[:user_sessions].insert(session_data)

      # Enhanced audit logging
      log_event(account_id, 'session_created', ip_address, user_agent, {
        session_id: session_id,
        session_token: "#{token_hash[0..8]}...",
        expires_at: expires_at,
        security_level: session_data[:security_level],
        success: true
      })

      token
    end

    # Enhanced session validation with security checks
    def validate_session(session_token, ip_address, user_agent)
      return nil unless session_token
      return nil unless session_token.length == SESSION_TOKEN_LENGTH * 2

      token_hash = hash_session_token(session_token)
      session = DB[:user_sessions]
                .where(session_token: token_hash, revoked: false)
                .where { expires_at > Time.now }
                .first

      return nil unless session

      # Enhanced security validations
      unless validate_session_security(session, ip_address, user_agent)
        revoke_session_by_hash(token_hash, 'security_violation')
        return nil
      end

      # Update session activity
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

    # Enhanced session revocation by hash
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

    # Enhanced mass session revocation
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

      # Log each revoked session
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

    # Enhanced active sessions retrieval
    def get_active_sessions(account_id)
      DB[:user_sessions]
        .where(account_id: account_id, revoked: false)
        .where { expires_at > Time.now }
        .reverse(:last_accessed_at)
        .all
        .map { |session| enhance_session_info(session) }
    end

    # Enhanced session token comparison
    def token_matches_session?(session_token, stored_hash)
      return false unless session_token && stored_hash
      return false unless session_token.length == SESSION_TOKEN_LENGTH * 2

      calculated_hash = hash_session_token(session_token)
      
      # Use secure comparison
      if defined?(OpenSSL.secure_compare)
        OpenSSL.secure_compare(calculated_hash, stored_hash)
      else
        calculated_hash == stored_hash
      end
    end

    # Enhanced session cleanup
    def cleanup_expired_sessions
      expired_count = DB[:user_sessions]
                      .where { expires_at < Time.now }
                      .where(revoked: false)
                      .update(
                        revoked: true, 
                        revoked_at: Time.now,
                        revocation_reason: 'expired'
                      )

      # Enhanced audit log cleanup
      old_logs = 0
      if DB.table_exists?(:audit_logs)
        retention_days = ENV.fetch('AUDIT_LOG_RETENTION_DAYS', '90').to_i
        cutoff_date = Time.now - (retention_days * 24 * 3600)
        
        old_logs = DB[:audit_logs]
                   .where { created_at < cutoff_date }
                   .delete
      end

      # Log cleanup if significant
      if expired_count > 0 || old_logs > 0
        log_event(nil, 'session_cleanup', nil, nil, {
          expired_sessions: expired_count,
          old_audit_logs: old_logs
        })
      end

      { expired_sessions: expired_count, old_logs: old_logs }
    end

    # Enhanced audit logging
    def log_event(account_id, event_type, ip_address, user_agent, details = {})
      return unless DB.table_exists?(:audit_logs)

      # Sanitize and enhance details
      sanitized_details = sanitize_audit_details(details)
      
      # Add security context
      sanitized_details[:timestamp] = Time.now.to_i
      sanitized_details[:security_context] = {
        ip_hash: ip_address ? Digest::SHA256.hexdigest("#{SESSION_SALT}:#{ip_address}")[0..7] : nil,
        user_agent_hash: user_agent ? Digest::SHA256.hexdigest("#{SESSION_SALT}:#{user_agent}")[0..7] : nil
      }

      DB[:audit_logs].insert(
        account_id: account_id,
        event_type: event_type,
        ip_address: sanitize_ip(ip_address),
        user_agent: sanitize_user_agent(user_agent),
        details: sanitized_details.to_json,
        success: details.fetch(:success, true),
        created_at: Time.now
      )
    end

    # Enhanced audit log retrieval
    def get_audit_log(account_id, limit = 50)
      return [] unless DB.table_exists?(:audit_logs)

      logs = DB[:audit_logs]
             .where(account_id: account_id)
             .reverse(:created_at)
             .limit(limit)
             .all

      # Parse and sanitize log details
      logs.map do |log|
        log[:details] = parse_audit_details(log[:details])
        log
      end
    end

    # Enhanced session fingerprinting
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

    # Generate cryptographically secure session token
    def generate_secure_session_token
      # Combine multiple entropy sources
      primary_entropy = SecureRandom.hex(SESSION_TOKEN_LENGTH)
      time_entropy = Time.now.to_f.to_s
      process_entropy = [Process.pid, $$].join(':')
      
      combined = "#{primary_entropy}:#{time_entropy}:#{process_entropy}"
      Digest::SHA256.hexdigest(combined)[0, SESSION_TOKEN_LENGTH * 2]
    end

    # Enhanced session token hashing
    def hash_session_token(token)
      # Use PBKDF2 for session token hashing
      iterations = 1000 # Lower iterations for session tokens (performance)
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

    # Validate account for session creation
    def validate_account_for_session(account)
      raise 'Account not verified' unless account[:verified]
      raise 'Account disabled' if account[:disabled]
      
      # Check for suspicious activity
      if account[:failed_login_count] && account[:failed_login_count] > 20
        raise 'Account temporarily locked due to suspicious activity'
      end
    end

    # Enhanced session security validation
    def validate_session_security(session, ip_address, user_agent)
      # Check for session hijacking indicators
      if session[:ip_address] && ip_address
        # Allow reasonable IP changes (same subnet)
        unless ip_addresses_compatible?(session[:ip_address], ip_address)
          log_event(session[:account_id], 'session_ip_mismatch', ip_address, user_agent, {
            original_ip: anonymize_ip(session[:ip_address]),
            new_ip: anonymize_ip(ip_address),
            success: false
          })
          return false
        end
      end

      # Check user agent consistency (allow minor variations)
      if session[:user_agent] && user_agent
        unless user_agents_compatible?(session[:user_agent], user_agent)
          log_event(session[:account_id], 'session_user_agent_mismatch', ip_address, user_agent, {
            original_ua_hash: Digest::SHA256.hexdigest(session[:user_agent])[0..7],
            new_ua_hash: Digest::SHA256.hexdigest(user_agent)[0..7],
            success: false
          })
          # Don't fail for user agent changes, just log
        end
      end

      # Check session age for regeneration
      if session_needs_regeneration?(session)
        log_event(session[:account_id], 'session_regeneration_needed', ip_address, user_agent, {
          session_age: Time.now - session[:created_at],
          success: true
        })
      end

      true
    end

    # Update session activity
    def update_session_activity(session, ip_address, user_agent)
      updates = {
        last_accessed_at: Time.now,
        access_count: (session[:access_count] || 0) + 1
      }

      # Update IP if changed
      if ip_address && session[:ip_address] != ip_address
        updates[:ip_address] = sanitize_ip(ip_address)
        
        log_event(session[:account_id], 'session_ip_updated', ip_address, user_agent, {
          old_ip: anonymize_ip(session[:ip_address]),
          new_ip: anonymize_ip(ip_address),
          success: true
        })
      end

      # Update user agent if changed
      if user_agent && session[:user_agent] != user_agent
        updates[:user_agent] = sanitize_user_agent(user_agent)
      end

      DB[:user_sessions].where(id: session[:id]).update(updates)
    end

    # Calculate security level for session
    def calculate_security_level(ip_address, user_agent)
      score = 0
      
      # IP address factors
      if ip_address
        score += 1 if ip_address.match?(/^192\.168\./) # Local network
        score += 1 if ip_address.match?(/^10\./) # Private network
        score -= 1 if ip_address.match?(/^[0-9.]+$/) && !ip_address.match?(/^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) # Public IP
      end
      
      # User agent factors
      if user_agent
        score += 1 if user_agent.include?('Chrome') || user_agent.include?('Firefox') # Trusted browsers
        score -= 1 if user_agent.include?('curl') || user_agent.include?('wget') # Command line tools
      end

      case score
      when 2..Float::INFINITY then 'high'
      when 0..1 then 'medium'
      else 'low'
      end
    end

    # Generate device fingerprint
    def generate_device_fingerprint(ip_address, user_agent)
      components = [
        ip_address&.split('.')&.first(3)&.join('.'), # Network portion of IP
        parse_user_agent(user_agent),
      ].compact.join(':')
      
      Digest::SHA256.hexdigest("#{SESSION_SALT}:#{components}")[0..15]
    end

    # Check if session needs regeneration
    def session_needs_regeneration?(session)
      return true unless session[:last_regenerated_at]
      
      (Time.now - session[:last_regenerated_at]) > SESSION_REGENERATION_INTERVAL
    end

    # Enhanced session limit enforcement
    def enforce_session_limit(account_id, account)
      active_sessions = DB[:user_sessions]
                       .where(account_id: account_id, revoked: false)
                       .where { expires_at > Time.now }
                       .all

      max_sessions = account[:max_concurrent_sessions] || MAX_CONCURRENT_SESSIONS

      if active_sessions.length >= max_sessions
        # Revoke oldest sessions
        sessions_to_revoke = active_sessions
                            .sort_by { |s| s[:last_accessed_at] }
                            .first(active_sessions.length - max_sessions + 1)

        sessions_to_revoke.each do |session|
          revoke_session_by_hash(session[:session_token], 'max_sessions_exceeded')
        end
      end
    end

    # Enhanced user agent parsing
    def parse_user_agent(user_agent)
      return 'Unknown' unless user_agent

      case user_agent
      when /Chrome\/(\d+)/i then "Chrome #{$1}"
      when /Firefox\/(\d+)/i then "Firefox #{$1}"
      when /Safari\/(\d+)/i then 'Safari'
      when /Edge\/(\d+)/i then "Edge #{$1}"
      when /Opera\/(\d+)/i then "Opera #{$1}"
      when /curl/i then 'curl'
      when /wget/i then 'wget'
      else 'Other'
      end
    end

    # Sanitize IP address
    def sanitize_ip(ip_address)
      return nil unless ip_address
      
      ip_address.to_s.strip.slice(0, 45)
    end

    # Sanitize user agent
    def sanitize_user_agent(user_agent)
      return nil unless user_agent
      
      user_agent.to_s.strip.gsub(/[^\x20-\x7E]/, '').slice(0, 1000)
    end

    # Anonymize IP for logging
    def anonymize_ip(ip_address)
      return 'unknown' unless ip_address
      
      parts = ip_address.split('.')
      if parts.length == 4
        "#{parts[0]}.#{parts[1]}.#{parts[2]}.xxx"
      else
        'anonymized'
      end
    end

    # Check IP address compatibility
    def ip_addresses_compatible?(ip1, ip2)
      return true if ip1 == ip2
      
      # Allow changes within same /24 subnet
      ip1_parts = ip1.split('.')
      ip2_parts = ip2.split('.')
      
      return false unless ip1_parts.length == 4 && ip2_parts.length == 4
      
      # Same /24 subnet
      ip1_parts[0..2] == ip2_parts[0..2]
    end

    # Check user agent compatibility
    def user_agents_compatible?(ua1, ua2)
      return true if ua1 == ua2
      
      # Extract browser and major version
      browser1 = parse_user_agent(ua1)
      browser2 = parse_user_agent(ua2)
      
      # Allow same browser family
      browser1.split(' ').first == browser2.split(' ').first
    end

    # Sanitize audit details
    def sanitize_audit_details(details)
      sanitized = {}
      
      details.each do |key, value|
        case value
        when String
          sanitized[key] = value.slice(0, 1000)
        when Numeric, TrueClass, FalseClass, NilClass
          sanitized[key] = value
        when Hash
          sanitized[key] = sanitize_audit_details(value)
        else
          sanitized[key] = value.to_s.slice(0, 1000)
        end
      end
      
      sanitized
    end

    # Parse audit details safely
    def parse_audit_details(details_json)
      return {} unless details_json
      
      JSON.parse(details_json)
    rescue JSON::ParserError
      { error: 'Invalid audit data' }
    end

    # Enhance session info
    def enhance_session_info(session)
      session[:fingerprint] = session_fingerprint(session)
      session
    end
  end
end
