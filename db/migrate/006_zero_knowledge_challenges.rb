# frozen_string_literal: true

Sequel.migration do
  change do
    # Update challenges table to store hashed codes
    alter_table :challenges do
      add_column :code_hash, String, size: 64
      add_column :created_at, DateTime, default: Sequel::CURRENT_TIMESTAMP
    end

    # Add indices for security
    alter_table :challenges do
      add_index :expires_at
      add_index %i[account_id expires_at]
    end

    # Add failed login tracking
    alter_table :accounts do
      add_column :last_failed_login_at, DateTime
      add_column :failed_login_count, Integer, default: 0
    end

    # Improve audit log
    alter_table :audit_logs do
      add_column :success, TrueClass, default: true
    end
  end
end
