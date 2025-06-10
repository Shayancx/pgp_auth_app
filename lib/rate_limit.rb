# frozen_string_literal: true

require_relative '../config/database'

# Enhanced rate limiting with sliding window and distributed protection
module RateLimit
  # Enhanced rate limiting configuration with sliding windows
  LIMITS = {
    'login' => { 
      max_attempts: 5, 
      window: 900, 
      backoff_base: 2,
      sliding_window: true,
      burst_protection: true
    },
    'password' => { 
      max_attempts: 10, 
      window: 3600, 
      backoff_base: 1.5,
      sliding_window: true,
      burst_protection: true
    },
    'register' => { 
      max_attempts: 3, 
      window: 3600, 
      backoff_base: 3,
      sliding_window: true,
      burst_protection: true
    },
    'verify_pgp' => { 
      max_attempts: 3, 
      window: 1800, 
      backoff_base: 2,
      sliding_window: true,
      burst_protection: true
    },
    '2fa' => { 
      max_attempts: 5, 
      window: 300, 
      backoff_base: 1.5,
      sliding_window: true,
      burst_protection: true
    }
  }.freeze

  # Password failure threshold for PGP-only mode
  PGP_ONLY_THRESHOLD = 10

  # Distributed rate limiting salt
  RATE_LIMIT_SALT = ENV.fetch('RATE_LIMIT_SALT', 'default_salt_change_in_production')

  class << self
    # Enhanced blocking check with sliding window
    def blocked?(identifier, action)
      cleanup_old_records

      config = LIMITS[action]
      return false unless config

      # Hash identifier to prevent enumeration
      hashed_identifier = hash_identifier(identifier, action)
      
      if config[:sliding_window]
        sliding_window_blocked?(hashed_identifier, action, config)
      else
        traditional_blocked?(hashed_identifier, action, config)
      end
    end

    # Enhanced attempt recording with burst protection
    def record_attempt(identifier, action)
      cleanup_old_records

      config = LIMITS[action]
      return false unless config

      hashed_identifier = hash_identifier(identifier, action)

      # Burst protection - check for rapid succession
      if config[:burst_protection] && burst_detected?(hashed_identifier, action)
        apply_burst_penalty(hashed_identifier, action, config)
        return true
      end

      if config[:sliding_window]
        record_sliding_window_attempt(hashed_identifier, action, config)
      else
        record_traditional_attempt(hashed_identifier, action, config)
      end
    end

    # Enhanced time until retry calculation
    def time_until_retry(identifier, action)
      hashed_identifier = hash_identifier(identifier, action)
      record = DB[:rate_limits].where(identifier: hashed_identifier, action: action).first
      return 0 unless record

      if record[:blocked_until] && record[:blocked_until] > Time.now
        (record[:blocked_until] - Time.now).to_i
      else
        0
      end
    end

    # Enhanced PGP-only mode check
    def pgp_only_required?(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      pgp_only_mode = account[:pgp_only_mode] || false
      failed_count = account[:failed_password_count] || 0

      pgp_only_mode || failed_count >= PGP_ONLY_THRESHOLD
    end

    # Enhanced password failure recording
    def record_password_failure(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      current_count = account[:failed_password_count] || 0
      new_count = current_count + 1
      pgp_only = new_count >= PGP_ONLY_THRESHOLD

      DB[:accounts].where(id: account[:id]).update(
        failed_password_count: new_count,
        pgp_only_mode: pgp_only,
        last_failed_login_at: Time.now
      )

      # Log security event
      SessionManager.log_event(account[:id], 'password_failure_recorded', nil, nil, {
        failed_count: new_count,
        pgp_only_triggered: pgp_only,
        success: false
      })

      record_attempt(username, 'password')
      pgp_only
    end

    # Reset password failures with comprehensive cleanup
    def reset_password_failures(username)
      account = DB[:accounts].where(username: username).first
      return unless account

      DB[:accounts].where(id: account[:id]).update(
        failed_password_count: 0,
        pgp_only_mode: false,
        last_failed_login_at: nil
      )

      # Clear related rate limit records
      hashed_identifier = hash_identifier(username, 'password')
      DB[:rate_limits].where(identifier: hashed_identifier, action: 'password').delete

      # Log security event
      SessionManager.log_event(account[:id], 'password_failures_reset', nil, nil, {
        success: true
      })
    end

    # Enhanced cleanup with configurable retention
    def cleanup_old_records
      retention_hours = ENV.fetch('RATE_LIMIT_RETENTION_HOURS', '48').to_i
      cutoff_time = Time.now - (retention_hours * 3600)
      
      deleted = DB[:rate_limits].where { last_attempt_at < cutoff_time }.delete
      
      # Log cleanup if significant
      if deleted > 100
        SessionManager.log_event(nil, 'rate_limit_cleanup', nil, nil, {
          deleted_records: deleted,
          retention_hours: retention_hours
        })
      end
      
      deleted
    end

    # Enhanced time formatting
    def format_time_remaining(seconds)
      return "0 seconds" if seconds <= 0
      
      if seconds < 60
        "#{seconds} seconds"
      elsif seconds < 3600
        minutes = seconds / 60
        remaining_seconds = seconds % 60
        if remaining_seconds > 0
          "#{minutes} minutes and #{remaining_seconds} seconds"
        else
          "#{minutes} minutes"
        end
      else
        hours = seconds / 3600
        minutes = (seconds % 3600) / 60
        if minutes > 0
          "#{hours} hours and #{minutes} minutes"
        else
          "#{hours} hours"
        end
      end
    end

    private

    # Hash identifier to prevent enumeration attacks
    def hash_identifier(identifier, action)
      Digest::SHA256.hexdigest("#{RATE_LIMIT_SALT}:#{action}:#{identifier}")[0..31]
    end

    # Sliding window blocking check
    def sliding_window_blocked?(hashed_identifier, action, config)
      window_start = Time.now - config[:window]
      
      recent_attempts = DB[:rate_limits]
                       .where(identifier: hashed_identifier, action: action)
                       .where { last_attempt_at > window_start }
                       .count

      # Check for current block
      record = DB[:rate_limits].where(identifier: hashed_identifier, action: action).first
      return true if record&.[](:blocked_until) && record[:blocked_until] > Time.now

      recent_attempts >= config[:max_attempts]
    end

    # Traditional blocking check (fallback)
    def traditional_blocked?(hashed_identifier, action, config)
      record = DB[:rate_limits].where(identifier: hashed_identifier, action: action).first
      return false unless record

      return true if record[:blocked_until] && record[:blocked_until] > Time.now

      record[:last_attempt_at] > Time.now - config[:window] && 
        record[:attempts] >= config[:max_attempts]
    end

    # Detect burst attempts (multiple attempts in short time)
    def burst_detected?(hashed_identifier, action)
      burst_window = 10 # seconds
      burst_threshold = 3 # attempts

      recent_attempts = DB[:rate_limits]
                       .where(identifier: hashed_identifier, action: action)
                       .where { last_attempt_at > Time.now - burst_window }
                       .count

      recent_attempts >= burst_threshold
    end

    # Apply penalty for burst attempts
    def apply_burst_penalty(hashed_identifier, action, config)
      penalty_duration = config[:window] * config[:backoff_base]
      blocked_until = Time.now + penalty_duration

      DB[:rate_limits]
        .where(identifier: hashed_identifier, action: action)
        .update(blocked_until: blocked_until, last_attempt_at: Time.now)
    end

    # Record attempt in sliding window
    def record_sliding_window_attempt(hashed_identifier, action, config)
      DB.transaction do
        # Clean old attempts outside window
        window_start = Time.now - config[:window]
        DB[:rate_limits]
          .where(identifier: hashed_identifier, action: action)
          .where { last_attempt_at < window_start }
          .delete

        # Count current attempts in window
        current_attempts = DB[:rate_limits]
                          .where(identifier: hashed_identifier, action: action)
                          .count

        # Insert new attempt
        DB[:rate_limits].insert(
          identifier: hashed_identifier,
          action: action,
          attempts: 1,
          first_attempt_at: Time.now,
          last_attempt_at: Time.now
        )

        # Check if we need to block
        if current_attempts + 1 >= config[:max_attempts]
          blocked_until = calculate_backoff_time(current_attempts + 1, config)
          DB[:rate_limits]
            .where(identifier: hashed_identifier, action: action)
            .update(blocked_until: blocked_until)
          
          return true
        end

        false
      end
    end

    # Record attempt traditionally
    def record_traditional_attempt(hashed_identifier, action, config)
      record = DB[:rate_limits].where(identifier: hashed_identifier, action: action).first

      if record
        if record[:last_attempt_at] > Time.now - config[:window]
          update_attempt_count(record, config)
        else
          reset_attempt_count(record[:id])
          false
        end
      else
        create_new_record(hashed_identifier, action)
        false
      end
    end

    # Calculate backoff time with jitter
    def calculate_backoff_time(attempts, config)
      base_delay = config[:window]
      backoff_multiplier = config[:backoff_base] ** (attempts - config[:max_attempts])
      
      # Add jitter to prevent thundering herd
      jitter = rand(0.8..1.2)
      delay = (base_delay * backoff_multiplier * jitter).to_i
      
      # Cap maximum delay to 24 hours
      delay = [delay, 86400].min
      
      Time.now + delay
    end

    # Update attempt count for existing record
    def update_attempt_count(record, config)
      new_attempts = record[:attempts] + 1
      blocked_until = if new_attempts >= config[:max_attempts]
                       calculate_backoff_time(new_attempts, config)
                     else
                       nil
                     end

      DB[:rate_limits].where(id: record[:id]).update(
        attempts: new_attempts,
        last_attempt_at: Time.now,
        blocked_until: blocked_until
      )

      new_attempts >= config[:max_attempts]
    end

    # Reset attempt count
    def reset_attempt_count(record_id)
      DB[:rate_limits].where(id: record_id).update(
        attempts: 1,
        first_attempt_at: Time.now,
        last_attempt_at: Time.now,
        blocked_until: nil
      )
    end

    # Create new rate limit record
    def create_new_record(hashed_identifier, action)
      DB[:rate_limits].insert(
        identifier: hashed_identifier,
        action: action,
        attempts: 1,
        first_attempt_at: Time.now,
        last_attempt_at: Time.now
      )
    end
  end
end
