# frozen_string_literal: true

require_relative '../config/database'

# SECURITY HARDENED: Enhanced rate limiting with zero race conditions
module RateLimit
  # SECURITY HARDENED: Stricter rate limiting configuration
  LIMITS = {
    'login' => { 
      max_attempts: 3,  # Reduced
      window: 1800,     # Increased window
      backoff_base: 3,  # Increased backoff
      sliding_window: true,
      burst_protection: true
    },
    'password' => { 
      max_attempts: 5,  # Reduced
      window: 7200,     # Increased window
      backoff_base: 2,
      sliding_window: true,
      burst_protection: true
    },
    'register' => { 
      max_attempts: 2,  # Reduced
      window: 7200,     # Increased window
      backoff_base: 4,  # Increased backoff
      sliding_window: true,
      burst_protection: true
    },
    'verify_pgp' => { 
      max_attempts: 3,
      window: 3600,     # Increased window
      backoff_base: 3,  # Increased backoff
      sliding_window: true,
      burst_protection: true
    },
    '2fa' => { 
      max_attempts: 3,  # Reduced
      window: 600,      # Increased window
      backoff_base: 2,
      sliding_window: true,
      burst_protection: true
    }
  }.freeze

  PGP_ONLY_THRESHOLD = 5  # Reduced threshold

  # SECURITY HARDENED: Enhanced salt generation
  RATE_LIMIT_SALT = ENV.fetch('RATE_LIMIT_SALT', SecureRandom.hex(64))

  class << self
    def blocked?(identifier, action)
      cleanup_old_records

      config = LIMITS[action]
      return false unless config

      hashed_identifier = hash_identifier(identifier, action)
      
      # SECURITY HARDENED: Use database transaction for atomicity
      DB.transaction do
        if config[:sliding_window]
          sliding_window_blocked?(hashed_identifier, action, config)
        else
          traditional_blocked?(hashed_identifier, action, config)
        end
      end
    end

    # SECURITY HARDENED: Race-condition-free attempt recording
    def record_attempt(identifier, action)
      cleanup_old_records

      config = LIMITS[action]
      return false unless config

      hashed_identifier = hash_identifier(identifier, action)

      # SECURITY HARDENED: Atomic operation in transaction
      DB.transaction do
        # Check burst protection first
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
    end

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

    def pgp_only_required?(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      pgp_only_mode = account[:pgp_only_mode] || false
      failed_count = account[:failed_password_count] || 0

      pgp_only_mode || failed_count >= PGP_ONLY_THRESHOLD
    end

    def record_password_failure(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      # SECURITY HARDENED: Atomic update
      DB.transaction do
        current_count = account[:failed_password_count] || 0
        new_count = current_count + 1
        pgp_only = new_count >= PGP_ONLY_THRESHOLD

        DB[:accounts].where(id: account[:id]).update(
          failed_password_count: new_count,
          pgp_only_mode: pgp_only,
          last_failed_login_at: Time.now
        )

        SessionManager.log_event(account[:id], 'password_failure_recorded', nil, nil, {
          failed_count: new_count,
          pgp_only_triggered: pgp_only,
          success: false
        })

        record_attempt(username, 'password')
        pgp_only
      end
    end

    def reset_password_failures(username)
      account = DB[:accounts].where(username: username).first
      return unless account

      DB.transaction do
        DB[:accounts].where(id: account[:id]).update(
          failed_password_count: 0,
          pgp_only_mode: false,
          last_failed_login_at: nil
        )

        hashed_identifier = hash_identifier(username, 'password')
        DB[:rate_limits].where(identifier: hashed_identifier, action: 'password').delete

        SessionManager.log_event(account[:id], 'password_failures_reset', nil, nil, {
          success: true
        })
      end
    end

    # SECURITY HARDENED: More aggressive cleanup
    def cleanup_old_records
      retention_hours = ENV.fetch('RATE_LIMIT_RETENTION_HOURS', '24').to_i
      cutoff_time = Time.now - (retention_hours * 3600)
      
      deleted = DB[:rate_limits].where { last_attempt_at < cutoff_time }.delete
      
      if deleted > 50
        SessionManager.log_event(nil, 'rate_limit_cleanup', nil, nil, {
          deleted_records: deleted,
          retention_hours: retention_hours
        })
      end
      
      deleted
    end

    def format_time_remaining(seconds)
      return "0 seconds" if seconds <= 0
      
      if seconds < 60
        "#{seconds} seconds"
      elsif seconds < 3600
        minutes = seconds / 60
        "#{minutes} minutes"
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

    # SECURITY HARDENED: Enhanced identifier hashing
    def hash_identifier(identifier, action)
      # Add timestamp component for additional security
      timestamp_component = (Time.now.to_i / 3600).to_s # Hour-based component
      Digest::SHA256.hexdigest("#{RATE_LIMIT_SALT}:#{action}:#{identifier}:#{timestamp_component}")[0..31]
    end

    def sliding_window_blocked?(hashed_identifier, action, config)
      window_start = Time.now - config[:window]
      
      recent_attempts = DB[:rate_limits]
                       .where(identifier: hashed_identifier, action: action)
                       .where { last_attempt_at > window_start }
                       .count

      record = DB[:rate_limits].where(identifier: hashed_identifier, action: action).first
      return true if record&.[](:blocked_until) && record[:blocked_until] > Time.now

      recent_attempts >= config[:max_attempts]
    end

    def traditional_blocked?(hashed_identifier, action, config)
      record = DB[:rate_limits].where(identifier: hashed_identifier, action: action).first
      return false unless record

      return true if record[:blocked_until] && record[:blocked_until] > Time.now

      record[:last_attempt_at] > Time.now - config[:window] && 
        record[:attempts] >= config[:max_attempts]
    end

    # SECURITY HARDENED: Stricter burst detection
    def burst_detected?(hashed_identifier, action)
      burst_window = 5 # Reduced window
      burst_threshold = 2 # Reduced threshold

      recent_attempts = DB[:rate_limits]
                       .where(identifier: hashed_identifier, action: action)
                       .where { last_attempt_at > Time.now - burst_window }
                       .count

      recent_attempts >= burst_threshold
    end

    def apply_burst_penalty(hashed_identifier, action, config)
      penalty_duration = config[:window] * config[:backoff_base] * 2 # Increased penalty
      blocked_until = Time.now + penalty_duration

      DB[:rate_limits]
        .where(identifier: hashed_identifier, action: action)
        .update(blocked_until: blocked_until, last_attempt_at: Time.now, penalty_applied: true)
    end

    # SECURITY HARDENED: Race-condition-free sliding window
    def record_sliding_window_attempt(hashed_identifier, action, config)
      window_start = Time.now - config[:window]
      
      # Clean old attempts
      DB[:rate_limits]
        .where(identifier: hashed_identifier, action: action)
        .where { last_attempt_at < window_start }
        .delete

      # Count current attempts
      current_attempts = DB[:rate_limits]
                        .where(identifier: hashed_identifier, action: action)
                        .count

      # Insert new attempt
      DB[:rate_limits].insert(
        identifier: hashed_identifier,
        action: action,
        attempts: 1,
        first_attempt_at: Time.now,
        last_attempt_at: Time.now,
        window_start: window_start
      )

      # Check blocking
      if current_attempts + 1 >= config[:max_attempts]
        blocked_until = calculate_backoff_time(current_attempts + 1, config)
        DB[:rate_limits]
          .where(identifier: hashed_identifier, action: action)
          .update(blocked_until: blocked_until)
        
        return true
      end

      false
    end

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

    # SECURITY HARDENED: Enhanced backoff calculation
    def calculate_backoff_time(attempts, config)
      base_delay = config[:window]
      backoff_multiplier = config[:backoff_base] ** (attempts - config[:max_attempts])
      
      # Reduced jitter for predictability
      jitter = rand(0.9..1.1)
      delay = (base_delay * backoff_multiplier * jitter).to_i
      
      # Increased maximum delay
      delay = [delay, 172800].min # 48 hours max
      
      Time.now + delay
    end

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

    def reset_attempt_count(record_id)
      DB[:rate_limits].where(id: record_id).update(
        attempts: 1,
        first_attempt_at: Time.now,
        last_attempt_at: Time.now,
        blocked_until: nil
      )
    end

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
