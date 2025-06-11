# frozen_string_literal: true

Sequel.migration do
  change do
    # Add security enhancements to existing tables
    alter_table :accounts do
      add_column :login_attempts_count, Integer, default: 0
      add_column :last_successful_login_at, DateTime
      add_column :security_level, String, size: 20, default: 'standard'
      add_column :account_locked, TrueClass, default: false
      add_column :lock_reason, String, size: 100
      add_column :locked_at, DateTime
      
      add_index :login_attempts_count
      add_index :account_locked
      add_index :security_level
    end

    alter_table :rate_limits do
      add_column :penalty_applied, TrueClass, default: false
      add_column :security_context, String, text: true
      
      add_index :penalty_applied
    end

    alter_table :user_sessions do
      add_column :fingerprint_hash, String, size: 64
      add_column :suspicious_activity_score, Integer, default: 0
      
      add_index :fingerprint_hash
      add_index :suspicious_activity_score
    end

    alter_table :audit_logs do
      add_column :risk_level, String, size: 20, default: 'low'
      add_column :investigation_required, TrueClass, default: false
      
      add_index :risk_level
      add_index :investigation_required
    end
  end
end
