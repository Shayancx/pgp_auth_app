# frozen_string_literal: true

module RateLimit
  # Tracks and manages rate limit attempts
  module Tracker
    module_function

    # Check if action is currently blocked for identifier
    def blocked?(identifier, action)
      RateLimit.cleanup_old_records

      config = Configuration::LIMITS[action]
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
      RateLimit.cleanup_old_records

      config = Configuration::LIMITS[action]
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
