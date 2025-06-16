# smail

Minimal email client for iCloud.

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
smail              # List emails
smail 0            # Read latest email
smail send "Subject" "Body"
smail send user@example.com "Subject" "Body"
```

## Security

Passwords are stored in macOS Keychain, never in files.
Use app-specific passwords from appleid.apple.com.

## TODO

- [ ] Support attachments
- [ ] Support replying (smail reply 0)
- [ ] Improve performance (connection reuse, parallel fetch)
- [ ] Delete/archive emails

right vis
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
