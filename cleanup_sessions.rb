#!/usr/bin/env ruby
# Cleanup script for expired sessions and old audit logs
# Run this periodically via cron job

require_relative "config/database"
require_relative "lib/session_manager"

puts "Cleaning up expired sessions and old audit logs..."
result = SessionManager.cleanup_expired_sessions
puts "Expired sessions: #{result[:expired_sessions]}"
puts "Old audit logs: #{result[:old_logs]}"
puts "Cleanup completed"
