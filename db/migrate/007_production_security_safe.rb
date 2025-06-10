# frozen_string_literal: true

Sequel.migration do
  change do
    # Remove plaintext code from challenges if it exists
    if DB[:challenges].columns.include?(:code)
      alter_table :challenges do
        drop_column :code
      end
    end

    # Add security indices if they don't exist
    alter_table :accounts do
      add_index :username, unique: true unless indexes.any? { |idx| idx[:columns] == [:username] }
      add_index :fingerprint, unique: true unless indexes.any? { |idx| idx[:columns] == [:fingerprint] }
      add_index %i[username verified] unless indexes.any? { |idx| idx[:columns] == %i[username verified] }
    end

    alter_table :user_sessions do
      add_index %i[session_token revoked] unless indexes.any? { |idx| idx[:columns] == %i[session_token revoked] }
    end
  end
end
