# frozen_string_literal: true

module RateLimit
  # Manages password failure policies and PGP-only mode
  module PasswordPolicy
    module_function

    # Check if account should be in PGP-only mode
    def pgp_only_required?(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      pgp_only_mode = account[:pgp_only_mode] || false
      failed_count = account[:failed_password_count] || 0

      pgp_only_mode || failed_count >= Configuration::PGP_ONLY_THRESHOLD
    end

    # Record password failure and potentially trigger PGP-only mode
    def record_password_failure(username)
      account = DB[:accounts].where(username: username, verified: true).first
      return false unless account

      current_count = account[:failed_password_count] || 0
      new_count = current_count + 1
      pgp_only = new_count >= Configuration::PGP_ONLY_THRESHOLD

      DB[:accounts].where(id: account[:id]).update(
        failed_password_count: new_count,
        pgp_only_mode: pgp_only
      )

      Tracker.record_attempt(username, 'password')
      pgp_only
    end

    # Reset password failure count (successful PGP challenge)
    def reset_password_failures(username)
      DB[:accounts].where(username: username).update(
        failed_password_count: 0,
        pgp_only_mode: false
      )
    end
  end
end
