# frozen_string_literal: true

Sequel.migration do
  change do
    # Accounts table with all security features
    create_table :accounts do
      primary_key :id
      String :username, null: false, unique: true
      String :password_hash, null: false
      String :public_key, text: true, null: false, unique: true
      String :fingerprint, null: false, unique: true
      TrueClass :verified, default: false, null: false
      String :verification_code, size: 64  # Hashed
      DateTime :verification_expires_at
      
      # Security enhancements
      Integer :failed_login_count, default: 0
      DateTime :last_failed_login_at
      Integer :failed_password_count, default: 0
      TrueClass :pgp_only_mode, default: false
      TrueClass :disabled, default: false
      DateTime :last_password_change
      TrueClass :require_password_change, default: false
      TrueClass :security_notifications, default: true
      
      # Session configuration
      Integer :session_timeout_hours, default: 24, null: false
      Integer :max_concurrent_sessions, default: 5, null: false
      
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      
      index :username, unique: true
      index :fingerprint, unique: true
      index [:username, :verified]
      index :last_password_change
      index [:disabled, :verified]
    end

    # Challenges table with zero-knowledge design
    create_table :challenges do
      primary_key :id
      foreign_key :account_id, :accounts, null: false
      String :code_hash, null: false, size: 64  # Hashed challenge - no plaintext
      DateTime :expires_at, null: false
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      
      index :expires_at
      index [:account_id, :expires_at]
    end

    # Enhanced rate limiting table
    create_table :rate_limits do
      primary_key :id
      String :identifier, null: false, size: 255  # Hashed IP/username
      String :action, null: false, size: 50
      Integer :attempts, default: 1, null: false
      DateTime :first_attempt_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :last_attempt_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :blocked_until
      DateTime :window_start
      TrueClass :penalty_applied, default: false
      
      index [:identifier, :action]
      index :last_attempt_at
      index [:identifier, :action, :window_start]
    end

    # Enhanced user sessions table
    create_table :user_sessions do
      primary_key :id
      foreign_key :account_id, :accounts, null: false
      String :session_token, null: false, unique: true, size: 64  # Hashed
      String :ip_address, size: 45
      String :user_agent, text: true
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :last_accessed_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :expires_at, null: false
      TrueClass :revoked, default: false, null: false
      DateTime :revoked_at
      String :revocation_reason, size: 100
      
      # Security enhancements
      Integer :access_count, default: 0
      DateTime :last_regenerated_at
      String :security_level, size: 20
      String :device_fingerprint, size: 32
      
      index :session_token, unique: true
      index :account_id
      index [:account_id, :revoked]
      index :expires_at
      index [:session_token, :revoked]
      index [:account_id, :security_level]
      index :device_fingerprint
    end

    # Comprehensive audit logs table
    create_table :audit_logs do
      primary_key :id
      foreign_key :account_id, :accounts
      String :event_type, null: false, size: 50
      String :ip_address, size: 45
      String :user_agent, text: true
      String :details, text: true
      TrueClass :success, default: true
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      
      index :account_id
      index :event_type
      index :created_at
      index [:account_id, :event_type]
    end
  end
end
