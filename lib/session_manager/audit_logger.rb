# frozen_string_literal: true

module SessionManager
  # Handles audit logging for security events
  module AuditLogger
    module_function

    # Log audit event
    def log_event(account_id, event_type, ip_address, user_agent, details = {})
      DB[:audit_logs].insert(
        account_id: account_id,
        event_type: event_type,
        ip_address: ip_address&.slice(0, 45),
        user_agent: user_agent&.slice(0, 1000),
        details: details.to_json
      )
    end

    # Get audit log for account
    def get_audit_log(account_id, limit = 50)
      DB[:audit_logs]
        .where(account_id: account_id)
        .order(:created_at.desc)
        .limit(limit)
        .all
    end
  end
end
