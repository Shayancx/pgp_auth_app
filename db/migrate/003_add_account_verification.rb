Sequel.migration do
  change do
    alter_table :accounts do
      add_column :verified, TrueClass, default: false, null: false
      add_column :verification_code, String
      add_column :verification_expires_at, DateTime
    end
  end
end
