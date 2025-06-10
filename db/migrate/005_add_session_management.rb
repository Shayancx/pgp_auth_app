Sequel.migration do
  change do
    create_table :user_sessions do
      primary_key :id
      foreign_key :account_id, :accounts, null: false
      String :session_token, null: false, unique: true, size: 64
      String :ip_address, size: 45  # IPv6 support
      String :user_agent, text: true
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :last_accessed_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :expires_at, null: false
      TrueClass :revoked, default: false, null: false
      DateTime :revoked_at
      
      index :session_token, name: :idx_sessions_token
      index :account_id, name: :idx_sessions_account
      index [:account_id, :revoked], name: :idx_sessions_active
      index :expires_at, name: :idx_sessions_cleanup
    end

    create_table :audit_logs do
      primary_key :id
      foreign_key :account_id, :accounts
      String :event_type, null: false, size: 50  # 'login', 'logout', 'login_failed', 'session_revoked'
      String :ip_address, size: 45
      String :user_agent, text: true
      String :details, text: true  # JSON details
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      
      index :account_id, name: :idx_audit_account
      index :event_type, name: :idx_audit_event
      index :created_at, name: :idx_audit_time
    end

    # Add session configuration to accounts
    alter_table :accounts do
      add_column :session_timeout_hours, Integer, default: 24, null: false
      add_column :max_concurrent_sessions, Integer, default: 5, null: false
    end
  end
end
