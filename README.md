# smail

Minimal email client for iCloud. Perfect for iCloud email aliases.

## Installation

```bash
# Install with uv (recommended)
uv tool install simplemail-cli

# Or use pipx
pipx install simplemail-cli
```


## Features

- Thread visualization with tree display
- Rich formatting with unread indicators
- Thread navigation (`smail 0.1`, `smail 0.last`)
- Quick self-email (`smail "reminder" "buy milk"`)
- Secure keychain password storage
- Reply tracking with proper threading
- Archive emails to iCloud Archive folder
- [ ] Unarchive emails (move back from Archive to Inbox)
- [ ] Attachments
- [ ] Performance optimization (connection reuse, parallel fetch)
- [ ] local `smail.toml` with just alias, so one can config per project email 

## Setup

### 1. Create App-Specific Password

1. Go to [appleid.apple.com](https://appleid.apple.com)
2. Sign in and navigate to "Sign-In and Security"
3. Select "App-Specific Passwords"
4. Click the "+" button to generate a new password

### 2. Create iCloud Email Alias (optional)

1. Go to [iCloud Mail settings](https://www.icloud.com/mail/) 
2. Click Settings → Accounts → Add Alias
3. Create an alias (e.g., yourname+smail@icloud.com)
4. Use this alias in your smail config to keep CLI emails separate

### 3. Configure smail

```bash
# First run guides you through setup
smail

# Or manually create config
cat > ~/.config/smail/config.toml << EOF
email = "your@icloud.com"           # your email alias address, will send emails from here and only show emails for this account
login = "your.appleid@icloud.com"  # Apple ID if different from email
keychain = "your-keychain-service"
EOF
```

### 4. Add Password to Keychain

```bash
# Add password from command line (macOS)
security add-generic-password \
  -a "your.appleid@icloud.com" \
  -s "your-keychain-service" \
  -w "your-app-specific-password"

# Or let smail prompt you on first run
smail
```

## Usage

```bash
# List & Read
smail                          # List emails
smail 0                        # Read email/thread
smail 0.1                      # Read specific message in thread
smail 0.last                   # Read newest message in thread

# Send
smail "Subject" "Body"                      # Send to self
smail user@example.com "Subject" "Body"     # Send to recipient

# Reply, Archive & Delete
smail reply "Quick reply"      # Reply to latest
smail 0 reply "Reply text"     # Reply to specific
smail 0 archive                # Archive email/thread
smail 0 delete                 # Delete email/thread
```

## Security

- Passwords are stored in macOS Keychain, never in files
- Always use app-specific passwords, not your main Apple ID password
- The keychain service name in config.toml should match the one used in the `security` command
