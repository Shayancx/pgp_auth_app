# frozen_string_literal: true

Sequel.migration do
  change do
    # Remove plaintext code from challenges if it exists
    alter_table :challenges do
      drop_column :code if columns.include?(:code)
    end

    # Add security indices
    alter_table :accounts do
      add_index :username, unique: true, if_not_exists: true
      add_index :fingerprint, unique: true, if_not_exists: true
      add_index %i[username verified], if_not_exists: true
    end

    alter_table :user_sessions do
      add_index %i[session_token revoked], if_not_exists: true
    end
  end
end
