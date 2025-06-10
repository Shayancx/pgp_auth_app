# frozen_string_literal: true

Sequel.migration do
  change do
    # Update challenges table to store hashed codes
    alter_table :challenges do
      add_column :code_hash, String, size: 64 unless columns.include?(:code_hash)
      # Only add created_at if it doesn't exist
      add_column :created_at, DateTime, default: Sequel::CURRENT_TIMESTAMP unless columns.include?(:created_at)
    end

    # Remove plaintext code from challenges if it exists
    if DB[:challenges].columns.include?(:code)
      alter_table :challenges do
        drop_column :code
      end
    end

    # Add indices for security if they don't exist
    alter_table :challenges do
      add_index :expires_at unless indexes.any? { |idx| idx[:columns] == [:expires_at] }
      add_index %i[account_id expires_at] unless indexes.any? { |idx| idx[:columns] == %i[account_id expires_at] }
    end

    # Add failed login tracking if not exists
    alter_table :accounts do
      add_column :last_failed_login_at, DateTime unless columns.include?(:last_failed_login_at)
      add_column :failed_login_count, Integer, default: 0 unless columns.include?(:failed_login_count)
    end

    # Improve audit log if column doesn't exist
    if DB.table_exists?(:audit_logs)
      alter_table :audit_logs do
        add_column :success, TrueClass, default: true unless columns.include?(:success)
      end
    end

    # Add security indices if they don't exist
    alter_table :accounts do
      add_index :username, unique: true unless indexes.any? { |idx| idx[:columns] == [:username] }
      add_index :fingerprint, unique: true unless indexes.any? { |idx| idx[:columns] == [:fingerprint] }
      add_index %i[username verified] unless indexes.any? { |idx| idx[:columns] == %i[username verified] }
    end

    if DB.table_exists?(:user_sessions)
      alter_table :user_sessions do
        add_index %i[session_token revoked] unless indexes.any? { |idx| idx[:columns] == %i[session_token revoked] }
      end
    end
  end
end
