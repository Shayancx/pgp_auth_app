#!/usr/bin/env ruby
# Session cleanup script

require_relative 'config/database'

puts "Clearing problematic session data..."

# Clear any sessions that might have bad data
if DB.table_exists?(:user_sessions)
  cleared = DB[:user_sessions].where(revoked: false).update(revoked: true, revocation_reason: 'cleanup')
  puts "Cleared #{cleared} active sessions"
end

puts "Session cleanup complete"
