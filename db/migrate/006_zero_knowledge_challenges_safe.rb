# frozen_string_literal: true

Sequel.migration do
  change do
    # Update challenges table to store hashed codes
    alter_table :challenges do
      add_column :code_hash, String, size: 64 unless columns.include?(:code_hash)
      add_column :created_at, DateTime, default: Sequel::CURRENT_TIMESTAMP unless columns.include?(:created_at)
    end

    # Add indices for security if they don't exist
    alter_table :challenges do
      add_index :expires_at unless indexes.include?(:challenges_expires_at_index)
      add_index %i[account_id expires_at] unless indexes.include?(:challenges_account_id_expires_at_index)
    end

    # Add failed login tracking if not exists
    alter_table :accounts do
      add_column :last_failed_login_at, DateTime unless columns.include?(:last_failed_login_at)
      add_column :failed_login_count, Integer, default: 0 unless columns.include?(:failed_login_count)
    end

    # Improve audit log if column doesn't exist
    alter_table :audit_logs do
      add_column :success, TrueClass, default: true unless columns.include?(:success)
    end
  end
end
