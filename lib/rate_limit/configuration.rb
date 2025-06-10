# frozen_string_literal: true

module RateLimit
  # Configuration for rate limiting rules
  module Configuration
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
  end
end
