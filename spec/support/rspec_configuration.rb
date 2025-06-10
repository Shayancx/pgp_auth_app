# frozen_string_literal: true

# RSpec configuration
RSpec.configure do |config|
  def app
    App
  end

  # Database Cleaner configuration
  config.before(:suite) do
    DatabaseCleaner[:sequel].strategy = :transaction
    DatabaseCleaner[:sequel].clean_with(:truncation)
    FactoryBot.find_definitions
  end

  config.around(:each) do |example|
    DatabaseCleaner[:sequel].cleaning do
      example.run
    end
  end

  config.after(:each) do
    Timecop.return
  end
end
