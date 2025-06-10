# frozen_string_literal: true

require_relative '../config/database'
require_relative 'rate_limit/configuration'
require_relative 'rate_limit/tracker'
require_relative 'rate_limit/password_policy'

# Main module for rate limiting functionality
module RateLimit
  extend Configuration
  extend Tracker
  extend PasswordPolicy

  module_function

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
end
