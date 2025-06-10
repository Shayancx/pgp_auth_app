#!/usr/bin/env ruby
# frozen_string_literal: true

# Cleanup script for old rate limit records
# Run this periodically via cron job

require_relative 'config/database'
require_relative 'lib/rate_limit'

puts 'Cleaning up old rate limit records...'
deleted = RateLimit.cleanup_old_records
puts "Deleted #{deleted} old records"

# Also cleanup sessions
require_relative 'lib/session_manager'
session_result = SessionManager.cleanup_expired_sessions
puts "Expired sessions: #{session_result[:expired_sessions]}"
puts "Old audit logs: #{session_result[:old_logs]}"
