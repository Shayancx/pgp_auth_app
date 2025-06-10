Sequel.migration do
  change do
    create_table :rate_limits do
      primary_key :id
      String :identifier, null: false, size: 255  # IP address or account ID
      String :action, null: false, size: 50       # 'login', 'register', 'verify_pgp', '2fa'
      Integer :attempts, default: 1, null: false
      DateTime :first_attempt_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :last_attempt_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :blocked_until
      
      index [:identifier, :action], name: :idx_rate_limits_lookup
      index :last_attempt_at, name: :idx_rate_limits_cleanup
    end
  end
end
