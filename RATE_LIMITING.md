# Rate Limiting Implementation

## Overview
This application implements intelligent rate limiting that distinguishes between legitimate form validation errors and actual security threats.

## Fixed Issues

### ❌ Before (Problematic)
- Users were penalized for basic form validation errors
- Empty usernames triggered rate limits
- Password complexity failures during registration counted as attempts
- PGP verification with empty codes counted as attempts

### ✅ After (Fixed)
- Rate limits only apply after meaningful validation passes
- Form validation errors don't trigger rate limiting
- Only actual authentication attempts are counted
- Smart distinction between user errors and potential attacks

## Rate Limiting Rules

### Registration
- **Triggers rate limit**: Duplicate username, invalid PGP key, actual account creation attempts
- **Does NOT trigger**: Empty fields, invalid username format, password complexity failures

### Login  
- **Triggers rate limit**: Valid username submitted (whether it exists or not)
- **Does NOT trigger**: Empty username submission

### Password Authentication
- **Triggers rate limit**: Actual password attempts (handled separately via `record_password_failure`)
- **Does NOT trigger**: Empty password submission

### PGP Verification/2FA
- **Triggers rate limit**: Valid code submission (whether correct or not)  
- **Does NOT trigger**: Empty code submission

## Benefits

1. **Better UX**: Users don't get locked out for simple mistakes
2. **Focused Security**: Rate limits target actual threats, not user errors
3. **Reduced False Positives**: Legitimate users less likely to hit limits
4. **Logical Behavior**: Rate limiting behaves as users would expect

## Monitoring

All rate limit events are logged with context in the audit log for security monitoring.
