#!/usr/bin/env ruby
require 'bundler/setup'
require 'net/http'
require 'uri'

puts "🧪 Testing basic app functionality..."

# Test home page
uri = URI('http://localhost:9292/')
response = Net::HTTP.get_response(uri)
puts response.code == '200' ? "✅ Home page loads" : "❌ Home page failed: #{response.code}"

# Test login page
uri = URI('http://localhost:9292/login')
response = Net::HTTP.get_response(uri)
puts response.code == '200' ? "✅ Login page loads" : "❌ Login page failed: #{response.code}"

# Test register page
uri = URI('http://localhost:9292/register')
response = Net::HTTP.get_response(uri)
puts response.code == '200' ? "✅ Register page loads" : "❌ Register page failed: #{response.code}"

puts "\nIf all pages load with ✅, the basic app structure is working!"
puts "You can now test the login flow manually in your browser."
