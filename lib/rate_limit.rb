# frozen_string_literal: true

require_relative '../config/database'

# Main module for rate limiting functionality
module RateLimit
  # Rate limiting configuration
  LIMITS = {
    'login' => { max_attempts: 5, window: 900, backoff_base: 2 },
    'password' => { max_attempts: 10, window: 3600, backoff_base: 1.5 },
    'register' => { max_attempts: 3, window: 3600, backoff_base: 3 },
    'verify_pgp' => { max_attempts: 3, window: 1800, backoff_base: 2 },
    '2fa' => { max_attempts: 5, window: 300, backoff_base: 1.5 }
  }.freeze

  # Password failure threshold for PGP-only mode
  PGP_ONLY_THRESHOLD = 10

  class << self
    # Check if action is currently blocked for identifier
    def blocked?(identifier, action)
      cleanup_old_records

      config = LIMITS[action]
      return false unless config

      record = DB[:rate_limits].where(identifier: identifier, action: action).first
      return false unless record

      # Check if currently blocked
      return true if record[:blocked_until] && record[:blocked_until] > Time.now

      # Check if within rate limit window and over threshold
      return record[:attempts] >= config[:max_attempts] if record[:last_attempt_at] > Time.now - config[:window]

      false
    end

    # Record an attempt and return whether it should be blocked
    def record_attempt(identifier, action)
      cleanup_old_records

      config = LIMITS[action]
      return false unless config

      record = DB[:rate_limits].where(identifier: identifier, action: action).first

      if record
        handle_existing_record(record, config)
      else
        create_new_record(identifier, action)
        false
      end
    end

    # Get time until user can try again
    def time_until_retry(identifier, action)
      record = DB[:rate_limits].where(identifier: identifier, action: action).first
      return 0 unless record

      return (record[:blocked_until] - Time.now).to_i if record[:blocked_until] && record[:blocked_until] > Time.now

      0
    end

    # Check if account should be in PGP-only mode
    def pgp_only_required?(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      pgp_only_mode = account[:pgp_only_mode] || false
      failed_count = account[:failed_password_count] || 0

      pgp_only_mode || failed_count >= PGP_ONLY_THRESHOLD
    end

    # Record password failure and potentially trigger PGP-only mode
    def record_password_failure(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      current_count = account[:failed_password_count] || 0
      new_count = current_count + 1
      pgp_only = new_count >= PGP_ONLY_THRESHOLD

      DB[:accounts].where(id: account[:id]).update(
        failed_password_count: new_count,
        pgp_only_mode: pgp_only
      )

      record_attempt(username, 'password')
      pgp_only
    end

    # Reset password failure count (successful PGP challenge)
    def reset_password_failures(username)
      DB[:accounts].where(username: username).update(
        failed_password_count: 0,
        pgp_only_mode: false
      )
    end

    # Clean up old rate limit records (older than 24 hours)
    def cleanup_old_records
      DB[:rate_limits].where { last_attempt_at < Time.now - 86_400 }.delete
    end

    # Get human-readable time remaining
    def format_time_remaining(seconds)
      if seconds < 60
        "#{seconds} seconds"
      elsif seconds < 3600
        minutes = seconds / 60
        "#{minutes} minutes"
      else
        hours = seconds / 3600
        minutes = (seconds % 3600) / 60
        if minutes.positive?
          "#{hours} hours and #{minutes} minutes"
        else
          "#{hours} hours"
        end
      end
    end

    private

    def handle_existing_record(record, config)
      if record[:last_attempt_at] > Time.now - config[:window]
        update_attempt_count(record, config)
      else
        reset_attempt_count(record[:id])
        false
      end
    end

    def update_attempt_count(record, config)
      new_attempts = record[:attempts] + 1
      blocked_until = calculate_blocked_until(new_attempts, config)

      DB[:rate_limits].where(id: record[:id]).update(
        attempts: new_attempts,
        last_attempt_at: Time.now,
        blocked_until: blocked_until
      )

      new_attempts >= config[:max_attempts]
    end

    def calculate_blocked_until(attempts, config)
      return nil if attempts < config[:max_attempts]

      excess_attempts = attempts - config[:max_attempts] + 1
      backoff_seconds = (config[:backoff_base]**excess_attempts) * 60
      Time.now + backoff_seconds
    end

    def reset_attempt_count(record_id)
      DB[:rate_limits].where(id: record_id).update(
        attempts: 1,
        first_attempt_at: Time.now,
        last_attempt_at: Time.now,
        blocked_until: nil
      )
    end

    def create_new_record(identifier, action)
      DB[:rate_limits].insert(
        identifier: identifier,
        action: action,
        attempts: 1,
        first_attempt_at: Time.now,
        last_attempt_at: Time.now
      )
    end
  end
end
