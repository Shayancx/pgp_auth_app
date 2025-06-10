# frozen_string_literal: true

Sequel.migration do
  change do
    alter_table :accounts do
      add_column :username, String, null: false, unique: true
      add_column :password_hash, String, null: false
      add_index :username
    end
  end
end
