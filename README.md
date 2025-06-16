# smail

Minimal email client for iCloud.

## Features

- Thread visualization with tree display
- Rich formatting with unread indicators
- Thread navigation (`smail 0.1`, `smail 0.last`)
- Quick self-email (`smail "reminder" "buy milk"`)
- Secure keychain password storage
- Reply tracking with proper threading
- [ ] Attachments
- [ ] Performance optimization (connection reuse, parallel fetch)

## Setup

```bash
# First run guides you through setup
smail

# Or manually create config
cat > ~/.config/smail/config.toml << EOF
email = "your@icloud.com"
login = "your.appleid@icloud.com"  # if different
keychain = "your-keychain-service"
EOF
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

# Reply & Delete
smail reply "Quick reply"      # Reply to latest
smail 0 reply "Reply text"     # Reply to specific
smail 0 delete                 # Delete email/thread
```

## Security

Passwords are stored in macOS Keychain, never in files.
Use app-specific passwords from appleid.apple.com.

## Thread Visualization
```bash
  ╭───────────────────────────────{0}──────────────────────────────────────╮
  │ Test with name · Beneath The Mask (btmask@icloud.com) · 15m ago        │
  ├────────────────────────────────────────────────────────────────────────┤
  │ This should show my display name                                       │
  ╰─┬──────────────────────────────────────────────────────────────────────╯
    │
    │ ╭─────────────────────────────────{0.2}─────────────────────────────────╮
    │ │ Re: Test with name · Beneath The Mask (btmask@icloud.com) · 7m ago    │
    ├─┼───────────────────────────────────────────────────────────────────────┤
    │ │ haha                                                                  │
    │ ╰───────────────────────────────────────────────────────────────────────╯
    │
    │ ╭──────────────────────────────────{0.1}─────────────────────────────────╮
    │ │ Re: Test with name · Beneath The Mask (btmask@icloud.com) · 10m ago    │
    ├─┼────────────────────────────────────────────────────────────────────────┤
    │ │ hi fam                                                                 │
    │ ╰─┬──────────────────────────────────────────────────────────────────────╯
    │   │
    │   │ ╭───────────────────────────────{0.1.0}───────────────────────────────╮
    │   │ │ Re: Test with name · Beneath The Mask (btmask@icloud.com) · 4m ago  │
    │   ╰─┼─────────────────────────────────────────────────────────────────────┤
    │     │ hehe                                                                │
    │     ╰─────────────────────────────────────────────────────────────────────╯
    │
    │ ╭──────────────────────────────────{0.0}─────────────────────────────────╮
    │ │ Re: Test with name · Someone Else (other@example.com) · 2m ago         │
    ╰─┼────────────────────────────────────────────────────────────────────────┤
      │ Different branch at same level                                         │
      ╰────────────────────────────────────────────────────────────────────────╯
```
