Sequel.migration do
  change do
    create_table :accounts do
      primary_key :id
      String  :public_key,  text: true, null: false, unique: true
      String  :fingerprint, null: false, unique: true
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
    end

    create_table :challenges do
      primary_key :id
      foreign_key :account_id, :accounts
      String  :code,        null: false
      DateTime :expires_at, null: false
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
    end
  end
end
