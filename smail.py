#!/usr/bin/env python3
"""smail - Simple email client for iCloud"""

import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from datetime import datetime
import subprocess
import sys
import os
from email.utils import parsedate_to_datetime
import tomllib
from pathlib import Path
import json
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

# Minimal beautiful assert with same API as assert
def ensure(condition, message=""):
    if not condition:
        import traceback
        import inspect
        
        # Get the calling frame
        frame = inspect.currentframe().f_back
        filename = frame.f_code.co_filename
        line_number = frame.f_lineno
        function_name = frame.f_code.co_name
        
        # Read the source line
        with open(filename, 'r') as f:
            lines = f.readlines()
            source_line = lines[line_number - 1].strip()
        
        # Extract just the filename (not full path)
        short_filename = os.path.basename(filename)
        
        # Extract the condition from the ensure call
        import re
        match = re.search(r'ensure\((.*?),', source_line)
        condition_str = match.group(1) if match else source_line
        
        # Print beautiful error
        print(f"\n{Colors.DIM}{short_filename}:{line_number}{Colors.ENDC}")
        print(f"  {Colors.RED}{condition_str}{Colors.ENDC}")
        print(f"  {Colors.RED}↳{Colors.ENDC} {message if message else 'assertion failed'}\n")
        sys.exit(1)

# iCloud defaults
IMAP_SERVER = "imap.mail.me.com"
IMAP_PORT = 993
SMTP_SERVER = "smtp.mail.me.com"
SMTP_PORT = 587

# Cache management
CACHE_PATH = Path.home() / ".cache" / "smail" / "emails.json"

def save_cache(display_items):
    """Save display items to cache"""
    cache_data = {
        "timestamp": datetime.now().isoformat(),
        "display_items": display_items
    }
    
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_PATH, 'w') as f:
        json.dump(cache_data, f, indent=2)

def load_cache():
    """Load email data from cache"""
    if not CACHE_PATH.exists():
        return None
    
    try:
        with open(CACHE_PATH) as f:
            cache_data = json.load(f)
        return cache_data
    except Exception:
        return None

# Load configuration
def load_config():
    config_path = Path.home() / ".config" / "smail" / "config.toml"
    
    if not config_path.exists():
        # Create config directory if needed
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # First time setup guidance
        print(f"{Colors.BOLD}Welcome to smail!{Colors.ENDC}")
        print(f"\nLet's set up your iCloud email.\n")
        
        print(f"{Colors.DIM}You'll need:{Colors.ENDC}")
        print("1. Your iCloud email address (e.g., user@icloud.com)")
        print("2. Your Apple ID if different from your email")
        print("3. An app-specific password from appleid.apple.com\n")
        
        # Get user input
        email = input(f"{Colors.CYAN}Your iCloud email:{Colors.ENDC} ").strip()
        ensure(email and "@" in email, "Invalid email address")
        
        login = input(f"{Colors.CYAN}Your Apple ID [{email}]:{Colors.ENDC} ").strip()
        if not login:
            login = email
            
        name = input(f"{Colors.CYAN}Your display name (optional):{Colors.ENDC} ").strip()
        
        keychain_name = email.split("@")[0] + "-smail"
        
        # Create config file
        config_content = f'''email = "{email}"
login = "{login}"
keychain = "{keychain_name}"'''
        
        if name:
            config_content += f'\nname = "{name}"'
        
        with open(config_path, "w") as f:
            f.write(config_content)
        
        # Guide for password setup
        print(f"\n{Colors.GREEN}✓ Config created!{Colors.ENDC}")
        print(f"\nNow let's save your app-specific password securely.")
        print(f"{Colors.DIM}(Get one from https://appleid.apple.com → Sign-In and Security → App-Specific Passwords){Colors.ENDC}")
        print(f"\nRun this command and paste your password when prompted:")
        print(f"\n{Colors.YELLOW}security add-generic-password -a \"{login}\" -s \"{keychain_name}\" -w{Colors.ENDC}")
        print(f"\n{Colors.DIM}This stores your password in macOS Keychain, not in any files.{Colors.ENDC}")
        print(f"{Colors.DIM}smail retrieves it securely each time you use it.{Colors.ENDC}")
        sys.exit(0)
    
    with open(config_path, "rb") as f:
        config = tomllib.load(f)
    
    ensure("email" in config, "email required in config")
    ensure("keychain" in config, "keychain required in config")
    
    # Set defaults
    if "login" not in config:
        config["login"] = config["email"]
    
    return config

# Load config
config = load_config()

# Configuration from file
EMAIL = config["email"]
LOGIN = config.get("login", EMAIL)
KEYCHAIN_SERVICE = config["keychain"]
NAME = config.get("name", "")  # Display name for emails

def get_password():
    """Get password from macOS keychain"""
    result = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
        capture_output=True, text=True
    )
    ensure(result.returncode == 0, f"""Password not found in keychain.

To add your app-specific password, run:
security add-generic-password -a "{LOGIN}" -s "{KEYCHAIN_SERVICE}" -w

Get an app-specific password from:
https://appleid.apple.com → Sign-In and Security → App-Specific Passwords""")
    
    password = result.stdout.strip()
    ensure(password, f"Empty password from keychain service '{KEYCHAIN_SERVICE}'")
    return password

def decode_mime_string(s):
    """Decode MIME encoded string"""
    ensure(s is not None, "Cannot decode None")
    if not s:
        return ""
    decoded_parts = []
    for part, encoding in decode_header(s):
        if isinstance(part, bytes):
            decoded_parts.append(part.decode(encoding or 'utf-8'))
        else:
            decoded_parts.append(part)
    return ''.join(decoded_parts)

def format_date(date_str):
    """Format date for display"""
    ensure(date_str, "Date string is required")
    dt = parsedate_to_datetime(date_str)
    ensure(dt, f"Could not parse date: {date_str}")
    
    now = datetime.now(dt.tzinfo)
    diff = now - dt
    
    if diff.days == 0:
        if diff.seconds < 3600:
            return f"{diff.seconds // 60}m ago"
        else:
            return f"{diff.seconds // 3600}h ago"
    elif diff.days == 1:
        return "yesterday"
    elif diff.days < 7:
        return f"{diff.days}d ago"
    else:
        return dt.strftime("%b %d")

class ThreadNode:
    """Represents a message in a thread tree"""
    def __init__(self, message):
        self.message = message
        self.children = []
        self.newest_date = parsedate_to_datetime(message['date'])
        self.thread_id = None  # Will be assigned after tree is built
    
    def update_newest_date(self):
        """Update newest_date based on children"""
        dates = [self.newest_date]
        for child in self.children:
            child.update_newest_date()
            dates.append(child.newest_date)
        self.newest_date = max(dates)
    
    def sort_children_by_newest(self):
        """Sort children by their newest date (newest last)"""
        self.children.sort(key=lambda x: x.newest_date)
        for child in self.children:
            child.sort_children_by_newest()

def assign_thread_ids(root):
    """Assign thread IDs to all nodes based on newest activity in each branch"""
    # First, assign root ID
    root.thread_id = "0"
    
    # Recursive function to assign IDs to children
    def assign_children_ids(parent):
        if not parent.children:
            return
        
        # Sort children by their newest_date (newest activity first)
        children_sorted = sorted(parent.children, key=lambda x: x.newest_date, reverse=True)
        
        # Assign IDs
        for i, child in enumerate(children_sorted):
            child.thread_id = f"{parent.thread_id}.{i}"
            # Recursively assign to grandchildren
            assign_children_ids(child)
    
    assign_children_ids(root)

def build_thread_tree(messages):
    """Build a proper thread tree from messages"""
    # Create nodes
    nodes = {msg['message_id']: ThreadNode(msg) for msg in messages}
    roots = []
    
    # Build tree structure
    for msg in messages:
        msg_id = msg['message_id']
        reply_to = msg['in_reply_to']
        
        if reply_to and reply_to in nodes:
            # Add as child to parent
            nodes[reply_to].children.append(nodes[msg_id])
        else:
            # Root message
            roots.append(nodes[msg_id])
    
    # Update newest dates and sort
    for root in roots:
        root.update_newest_date()
        root.sort_children_by_newest()
        # Assign thread IDs
        assign_thread_ids(root)
    
    return roots

def flatten_thread_tree(root, result=None, depth=0):
    """Flatten thread tree into display order with depth info"""
    if result is None:
        result = []
    
    result.append((root.message, depth))
    
    for child in root.children:
        flatten_thread_tree(child, result, depth + 1)
    
    return result

def build_threads(emails):
    """Build thread relationships from email list"""
    # First pass: build a map of message_id to email
    msg_map = {e['message_id']: e for e in emails}
    
    # Second pass: find root for each message
    def find_root(msg_id, visited=None):
        if visited is None:
            visited = set()
        if msg_id in visited:
            return msg_id  # Circular reference, use self as root
        visited.add(msg_id)
        
        if msg_id not in msg_map:
            return msg_id  # Message not in our set
        
        msg = msg_map[msg_id]
        if not msg['in_reply_to']:
            return msg_id  # This is a root
        
        # Recurse to find ultimate root
        return find_root(msg['in_reply_to'], visited)
    
    # Group by thread root
    threads = {}
    for email_data in emails:
        root_id = find_root(email_data['message_id'])
        if root_id not in threads:
            threads[root_id] = []
        threads[root_id].append(email_data)
    
    # Sort messages within each thread by date
    for thread_id in threads:
        threads[thread_id].sort(key=lambda x: parsedate_to_datetime(x['date']))
    
    return threads

def list_emails(max_emails=20, expand_thread=None, display=True, from_cache=False):
    """List emails to/from btmask@icloud.com with thread support"""
    # If loading from cache for display
    if from_cache and display:
        cache_data = load_cache()
        ensure(cache_data, "No cached email data found. Run 'smail' first to fetch emails.")
        
        emails_data = cache_data['emails']
        idx_mapping = cache_data['idx_mapping']
        
        # Rebuild threads from cache
        threads = {}
        for thread_id, email_ids in cache_data['threads'].items():
            thread_emails = []
            # Preserve order from the thread data
            for email_id in email_ids:
                for e in emails_data:
                    if e['id'] == email_id:
                        thread_emails.append(e)
                        break
            if thread_emails:
                threads[thread_id] = thread_emails
        
        # Just display from cache
        _display_emails(emails_data, threads, expand_thread, idx_mapping)
        return idx_mapping
    
    # If just loading cache data without display (for read operations)
    if not display:
        cache_data = load_cache()
        ensure(cache_data, "No cached email data found. Run 'smail' first to fetch emails.")
        return cache_data['idx_mapping']
    
    # Otherwise, fetch fresh data
    password = get_password()
    
    # Connect to IMAP
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(LOGIN, password)
    mail.select('INBOX')
    
    # Search for emails to/from our email
    typ, to_data = mail.search(None, f'(TO "{EMAIL}")')
    ensure(typ == 'OK', f"Search failed: {typ}")
    to_ids = to_data[0].split() if to_data[0] else []
    
    typ, from_data = mail.search(None, f'(FROM "{EMAIL}")')
    ensure(typ == 'OK', f"Search failed: {typ}")
    from_ids = from_data[0].split() if from_data[0] else []
    
    # Combine and deduplicate
    all_ids = list(set(to_ids + from_ids))
    all_ids.sort(key=lambda x: int(x.decode() if isinstance(x, bytes) else x), reverse=True)
    
    # Limit number of emails
    email_ids = all_ids[:max_emails]
    
    if not email_ids:
        print(f"{Colors.DIM}No emails found{Colors.ENDC}")
        return
    
    # Fetch all emails and extract threading info
    emails_data = []
    
    for email_id in email_ids:
        # email_id might be bytes
        if isinstance(email_id, bytes):
            email_id = email_id.decode()
        
        # Fetch email body and flags without marking as read
        typ, msg_data = mail.fetch(email_id, '(FLAGS BODY.PEEK[])')
        ensure(typ == 'OK', f"IMAP fetch failed: {typ}")
        ensure(msg_data, "No message data returned")
        ensure(len(msg_data) >= 1, f"Expected at least 1 item in msg_data, got {len(msg_data)}")
        
        # IMAP response handling
        ensure(msg_data[0] is not None, f"Failed to fetch email {email_id}")
        
        # Parse FLAGS and BODY from response
        flags = []
        raw_email = None
        
        # The response contains FLAGS and BODY data
        if isinstance(msg_data[0], tuple) and len(msg_data[0]) == 2:
            # Response line and data
            response_line = msg_data[0][0].decode() if isinstance(msg_data[0][0], bytes) else msg_data[0][0]
            
            # Extract flags from response line
            if 'FLAGS' in response_line:
                import re
                flags_match = re.search(r'FLAGS \(([^)]*)\)', response_line)
                if flags_match:
                    flags = flags_match.group(1).split()
            
            raw_email = msg_data[0][1]
        else:
            # Fallback for unexpected format
            raw_email = msg_data[0] if isinstance(msg_data[0], bytes) else msg_data[0][1]
        
        ensure(isinstance(raw_email, bytes), f"Expected bytes for email body, got {type(raw_email)}")
        
        # Check if email is read
        is_read = '\\Seen' in flags
        
        msg = email.message_from_bytes(raw_email)
        
        # Extract headers including threading
        subject = decode_mime_string(msg.get('Subject') or 'No Subject')
        from_addr = decode_mime_string(msg.get('From') or 'Unknown')
        date = msg.get('Date')
        message_id = msg.get('Message-ID', '').strip('<>')
        in_reply_to = msg.get('In-Reply-To', '').strip('<>')
        references = msg.get('References', '')
        
        # Handle incomplete emails (server still processing)
        if not date:
            print(f"{Colors.YELLOW}Waiting for server to process new messages...{Colors.ENDC}")
            time.sleep(2)
            
            # Retry fetching this specific email
            typ, msg_data = mail.fetch(email_id, '(FLAGS BODY.PEEK[])')
            ensure(typ == 'OK', f"IMAP retry fetch failed: {typ}")
            
            # Re-parse the message and flags
            flags = []
            if isinstance(msg_data[0], tuple) and len(msg_data[0]) == 2:
                response_line = msg_data[0][0].decode() if isinstance(msg_data[0][0], bytes) else msg_data[0][0]
                if 'FLAGS' in response_line:
                    import re
                    flags_match = re.search(r'FLAGS \(([^)]*)\)', response_line)
                    if flags_match:
                        flags = flags_match.group(1).split()
                raw_email = msg_data[0][1]
            else:
                raw_email = msg_data[0] if isinstance(msg_data[0], bytes) else msg_data[0][1]
            
            is_read = '\\Seen' in flags
            
            msg = email.message_from_bytes(raw_email)
            
            # Re-extract headers
            subject = decode_mime_string(msg.get('Subject') or 'No Subject')
            from_addr = decode_mime_string(msg.get('From') or 'Unknown')
            date = msg.get('Date')
            message_id = msg.get('Message-ID', '').strip('<>')
            in_reply_to = msg.get('In-Reply-To', '').strip('<>')
            references = msg.get('References', '')
            
            ensure(date, f"Email {email_id} incomplete after retry - server issue")
        
        # Clean up from address
        if '<' in from_addr:
            display_name = from_addr.split('<')[0].strip()
            email_addr = from_addr.split('<')[1].split('>')[0]
            if display_name and display_name != email_addr:
                # Show both name and email
                from_name = f"{display_name} ({email_addr})"
            else:
                # Just show email if no name or they're the same
                from_name = email_addr
        else:
            from_name = from_addr
        
        ensure(from_name, f"Could not extract from name from {from_addr}")
        
        # Extract body for caching
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                    break
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
        
        emails_data.append({
            'id': email_id,
            'subject': subject,
            'from': from_name,
            'from_full': from_addr,  # Keep full address too
            'date': date,
            'message_id': message_id,
            'in_reply_to': in_reply_to,
            'references': references,
            'body': body,
            'is_read': is_read
        })
    
    # Build threads
    threads = build_threads(emails_data)
    
    # Display emails with thread grouping
    idx_mapping = _display_emails(emails_data, threads, expand_thread, {} if display else None)
    
    # Save to cache when fetching fresh
    if display:
        save_cache(emails_data, threads, idx_mapping)
    
    mail.close()
    mail.logout()
    
    # Return mapping for potential reading
    return idx_mapping

def _display_emails(emails_data, threads, expand_thread, idx_mapping):
    """Display emails with thread grouping"""
    # If idx_mapping is None, we're not displaying
    if idx_mapping is None:
        return {}
    
    # Print header
    print(f"\n{Colors.BOLD}{'  ID':<6} {'SUBJECT':<40} {'FROM':<35} {'DATE':<12}{Colors.ENDC}")
    print(f"{Colors.DIM}{'─' * 94}{Colors.ENDC}")
    displayed_messages = set()
    display_idx = 0
    idx_to_email = {}  # Map display index to email data
    
    for email_data in emails_data:
        if email_data['message_id'] in displayed_messages:
            continue
            
        thread_id = None
        thread_messages = []
        
        # Find thread for this message
        for tid, messages in threads.items():
            if any(m['message_id'] == email_data['message_id'] for m in messages):
                thread_id = tid
                thread_messages = messages
                break
        
        # Show thread or single message
        if len(thread_messages) > 1 and expand_thread != display_idx:
            # Collapsed thread - show latest message
            latest = thread_messages[-1]
            
            # Truncate if needed
            from_name = latest['from']
            if len(from_name) > 34:
                from_name = from_name[:31] + "..."
            
            # Clean subject - remove "Re: " prefix
            subject = latest['subject']
            if subject.lower().startswith('re: '):
                subject = subject[4:]
            
            # Add thread count
            subject_with_count = f"{subject} ({len(thread_messages)})"
            if len(subject_with_count) > 39:
                # Truncate subject part, keep count
                max_subj_len = 39 - len(f" ({len(thread_messages)})")
                subject = subject[:max_subj_len - 3] + "..."
                subject_with_count = f"{subject} ({len(thread_messages)})"
            
            # Format date
            date_str = format_date(latest['date'])
            
            # Check if thread has any unread messages
            has_unread = any(not m.get('is_read', True) for m in thread_messages)
            
            # Format with dot and bold if unread
            if has_unread:
                print(f"{Colors.BOLD}● {display_idx:<4} {subject_with_count:<40} {Colors.CYAN}{from_name:<35}{Colors.ENDC} {Colors.BOLD}{date_str:<12}{Colors.ENDC}")
            else:
                print(f"  {Colors.DIM}{display_idx:<4}{Colors.ENDC} {subject_with_count:<40} {Colors.DIM}{Colors.CYAN}{from_name:<35}{Colors.ENDC} {Colors.DIM}{date_str:<12}{Colors.ENDC}")
            
            idx_to_email[display_idx] = latest
            for m in thread_messages:
                displayed_messages.add(m['message_id'])
            display_idx += 1
            
        elif len(thread_messages) > 1 and expand_thread == display_idx:
            # Expanded thread - show all messages
            for i, msg in enumerate(thread_messages):
                # Truncate if needed
                from_name = msg['from']
                if len(from_name) > 34:
                    from_name = from_name[:31] + "..."
                subject = msg['subject']
                if len(subject) > 36:
                    subject = subject[:33] + "..."
                
                # Format date
                date_str = format_date(msg['date'])
                
                # Add thread indicator
                if i > 0:
                    subject = "↳ " + subject
                
                # Check if message is unread
                is_unread = not msg.get('is_read', True)
                
                # Format with dot and bold if unread
                if is_unread:
                    print(f"{Colors.BOLD}● {display_idx:<4} {subject:<40} {Colors.CYAN}{from_name:<35}{Colors.ENDC} {Colors.BOLD}{date_str:<12}{Colors.ENDC}")
                else:
                    print(f"  {Colors.DIM}{display_idx:<4}{Colors.ENDC} {subject:<40} {Colors.DIM}{Colors.CYAN}{from_name:<35}{Colors.ENDC} {Colors.DIM}{date_str:<12}{Colors.ENDC}")
                
                idx_to_email[display_idx] = msg
                displayed_messages.add(msg['message_id'])
                display_idx += 1
        else:
            # Single message
            # Truncate if needed
            from_name = email_data['from']
            if len(from_name) > 34:
                from_name = from_name[:31] + "..."
            
            # Clean subject - remove "Re: " prefix
            subject = email_data['subject']
            if subject.lower().startswith('re: '):
                subject = subject[4:]
            
            if len(subject) > 39:
                subject = subject[:36] + "..."
            
            # Format date
            date_str = format_date(email_data['date'])
            
            # Check if message is unread
            is_unread = not email_data.get('is_read', True)
            
            # Format with dot and bold if unread
            if is_unread:
                print(f"{Colors.BOLD}● {display_idx:<4} {subject:<40} {Colors.CYAN}{from_name:<35}{Colors.ENDC} {Colors.BOLD}{date_str:<12}{Colors.ENDC}")
            else:
                print(f"  {Colors.DIM}{display_idx:<4}{Colors.ENDC} {subject:<40} {Colors.DIM}{Colors.CYAN}{from_name:<35}{Colors.ENDC} {Colors.DIM}{date_str:<12}{Colors.ENDC}")
            
            idx_to_email[display_idx] = email_data
            displayed_messages.add(email_data['message_id'])
            display_idx += 1
    
    return idx_to_email

def send_email(recipient, subject, body, in_reply_to=None):
    """Send an email"""
    password = get_password()
    
    # Create message
    msg = MIMEMultipart()
    # Use display name if configured
    if NAME:
        msg['From'] = f"{NAME} <{EMAIL}>"
    else:
        msg['From'] = EMAIL
    msg['To'] = recipient
    msg['Subject'] = subject
    
    # Add threading headers if replying
    if in_reply_to:
        msg['In-Reply-To'] = f"<{in_reply_to}>"
        msg['References'] = f"<{in_reply_to}>"
    
    msg.attach(MIMEText(body, 'plain'))
    
    # Connect to SMTP
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(LOGIN, password)
    
    # Send email
    server.send_message(msg)
    server.quit()
    
    print(f"{Colors.GREEN}✓ Email sent to {recipient}{Colors.ENDC}")

def mark_emails_as_read(email_ids):
    """Mark emails as read in IMAP"""
    password = get_password()
    
    # Connect to IMAP
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(LOGIN, password)
    mail.select('INBOX')
    
    # Mark each email as read
    for email_id in email_ids:
        try:
            mail.store(email_id, '+FLAGS', '\\Seen')
        except Exception as e:
            # Continue even if one fails
            print(f"{Colors.YELLOW}Warning: Could not mark email {email_id} as read: {e}{Colors.ENDC}")
    
    mail.close()
    mail.logout()

def read_email(email_ref, idx_to_email=None):
    """Read a specific email or thread by number (e.g., 0 or 0.1)"""
    if idx_to_email is None:
        # Load from cache
        cache_data = load_cache()
        ensure(cache_data, "No cached email data found. Run 'smail' first to fetch emails.")
        idx_to_email = cache_data['idx_mapping']
        emails_data = cache_data['emails']
        threads = {}
        for thread_id, email_ids in cache_data['threads'].items():
            thread_emails = []
            # Preserve order from the thread data
            for email_id in email_ids:
                for e in emails_data:
                    if e['id'] == email_id:
                        thread_emails.append(e)
                        break
            if thread_emails:
                threads[thread_id] = thread_emails
    
    # Track which emails to mark as read
    emails_to_mark_read = []
    
    # Parse email reference (e.g., "0" or "0.1")
    if '.' in str(email_ref):
        # Thread message reference (e.g., 0.1)
        parts = str(email_ref).split('.')
        thread_idx = int(parts[0])
        msg_idx = int(parts[1])
        
        ensure(thread_idx in idx_to_email, f"Invalid thread number. Choose between 0 and {len(idx_to_email) - 1}")
        
        # Find the thread for this index
        email_data = idx_to_email[thread_idx]
        thread_id = None
        thread_messages = []
        
        for tid, messages in threads.items():
            if any(m['message_id'] == email_data['message_id'] for m in messages):
                thread_id = tid
                thread_messages = messages
                break
        
        ensure(thread_messages, "No thread found for this email")
        ensure(0 <= msg_idx < len(thread_messages), f"Invalid message index. Choose between 0 and {len(thread_messages) - 1}")
        
        # Display specific message from thread (0 is newest)
        msg = thread_messages[-(msg_idx + 1)]  # Reverse index
        subject = msg['subject']
        from_name = msg['from']
        date_str = format_date(msg['date'])
        body = msg.get('body', '')
        
        print()
        print(f"{subject} {Colors.DIM}·{Colors.ENDC} {Colors.DIM}{Colors.CYAN}{from_name}{Colors.ENDC} {Colors.DIM}·{Colors.ENDC} {Colors.DIM}{date_str}{Colors.ENDC}")
        print(f"{Colors.DIM}{'─' * 80}{Colors.ENDC}")
        print()
        print(body)
        
        # Mark this single message as read if not already read
        if not msg.get('is_read', True):
            emails_to_mark_read.append(msg['id'])
        
    else:
        # Simple email/thread reference (e.g., 0)
        email_number = int(email_ref)
        ensure(email_number in idx_to_email, f"Invalid email number. Choose between 0 and {len(idx_to_email) - 1}")
        
        email_data = idx_to_email[email_number]
        
        # Check if this is part of a thread
        thread_id = None
        thread_messages = []
        
        for tid, messages in threads.items():
            if any(m['message_id'] == email_data['message_id'] for m in messages):
                thread_id = tid
                thread_messages = messages
                break
        
        if len(thread_messages) > 1:
            # Build thread tree
            tree_roots = build_thread_tree(thread_messages)
            
            # Should have exactly one root for a proper thread
            ensure(len(tree_roots) == 1, "Thread has multiple roots - data inconsistency")
            root = tree_roots[0]
            
            # Set parent references
            def set_parents(n, parent=None):
                n._parent = parent
                for child in n.children:
                    set_parents(child, n)
            set_parents(root)
            
            # Display the thread tree with proper boxes
            print()
            _display_thread_node(root, "", True, False)
            
            # Mark all unread messages in thread as read
            emails_to_mark_read.extend([msg['id'] for msg in thread_messages if not msg.get('is_read', True)])
        else:
            # Display single email
            subject = email_data['subject']
            from_name = email_data['from']
            date_str = format_date(email_data['date'])
            body = email_data.get('body', '')
            
            print()
            print(f"{subject} {Colors.DIM}·{Colors.ENDC} {Colors.DIM}{Colors.CYAN}{from_name}{Colors.ENDC} {Colors.DIM}·{Colors.ENDC} {Colors.DIM}{date_str}{Colors.ENDC}")
            print(f"{Colors.DIM}{'─' * 80}{Colors.ENDC}")
            print()
            print(body)
            
            # Mark this single email as read if not already read
            if not email_data.get('is_read', True):
                emails_to_mark_read.append(email_data['id'])
    
    # Mark emails as read
    if emails_to_mark_read:
        mark_emails_as_read(emails_to_mark_read)
        
        # Update cache to reflect read status
        cache_data = load_cache()
        if cache_data:
            # Update is_read status in cache
            for email in cache_data['emails']:
                if email['id'] in emails_to_mark_read:
                    email['is_read'] = True
            
            # Also update idx_mapping if present
            for idx, email in cache_data.get('idx_mapping', {}).items():
                if email['id'] in emails_to_mark_read:
                    email['is_read'] = True
            
            # Save updated cache - use the threads structure from cache
            save_cache(cache_data['emails'], 
                      cache_data['threads'], 
                      cache_data['idx_mapping'])

def _render_thread_with_rich(root):
    """Render thread using Rich with simple indentation"""
    console = Console()
    
    def render_node(node, depth=0):
        """Render a node with indentation"""
        msg = node.message
        subject = msg['subject']
        from_name = msg['from']
        date_str = format_date(msg['date'])
        body = msg.get('body', '')
        thread_ref = node.thread_id
        
        # Check if message is unread
        is_unread = not msg.get('is_read', True)
        
        # Build the panel content
        content = Text()
        
        # Add unread indicator if needed
        if is_unread:
            # Bold styling for unread messages
            content.append(f"{subject} · ", style="bold")
            content.append(from_name, style="bold cyan")
            content.append(f" · {date_str}", style="bold")
        else:
            content.append(f"{subject} · ", style="bold")
            content.append(from_name, style="cyan")
            content.append(f" · {date_str}", style="dim")
        
        content.append("\n")
        content.append("─" * 72, style="bright_black")  # Divider line
        content.append("\n")
        content.append(body.strip())
        
        # Create panel with unread indicator in title if needed
        title = f"[dim white]{{{thread_ref}}}[/dim white]"
        if is_unread:
            title = f"[bold white]●[/bold white] " + title
        
        panel = Panel(
            content,
            title=title,
            title_align="center",
            border_style="bold" if is_unread else "bright_black",
            padding=(0, 1),
            width=76,
            expand=False
        )
        
        # Print with indentation
        if depth > 0:
            from rich.padding import Padding
            padded = Padding(panel, (0, 0, 0, depth * 2))
            console.print(padded)
        else:
            console.print(panel)
        
        # Render children (reversed so newest is last)
        children_sorted = sorted(node.children, key=lambda x: int(x.thread_id.split('.')[-1]), reverse=True)
        for child in children_sorted:
            render_node(child, depth + 1)
    
    render_node(root)

def _display_thread_node(node, prefix="", is_last=True, parent_has_more=False):
    """Display a thread node - wrapper for Rich implementation"""
    # For the root call, use the Rich renderer
    if not prefix:  # Root node
        _render_thread_with_rich(node)

def delete_emails(email_ids):
    """Delete emails from IMAP"""
    password = get_password()
    
    # Connect to IMAP
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(LOGIN, password)
    mail.select('INBOX')
    
    # Mark each email for deletion
    deleted_count = 0
    for email_id in email_ids:
        try:
            mail.store(email_id, '+FLAGS', '\\Deleted')
            deleted_count += 1
        except Exception as e:
            print(f"{Colors.YELLOW}Warning: Could not delete email {email_id}: {e}{Colors.ENDC}")
    
    # Expunge to permanently delete
    mail.expunge()
    mail.close()
    mail.logout()
    
    return deleted_count

def delete_email(email_ref):
    """Delete a specific email or thread by number"""
    # Load from cache
    cache_data = load_cache()
    ensure(cache_data, "No cached email data found. Run 'smail' first to fetch emails.")
    
    idx_to_email = cache_data['idx_mapping']
    emails_data = cache_data['emails']
    threads = {}
    for thread_id, email_ids in cache_data['threads'].items():
        thread_emails = []
        for email_id in email_ids:
            for e in emails_data:
                if e['id'] == email_id:
                    thread_emails.append(e)
                    break
        if thread_emails:
            threads[thread_id] = thread_emails
    
    # Track which emails to delete
    emails_to_delete = []
    
    # Parse email reference (e.g., "0" or "0.1")
    if '.' in str(email_ref):
        # Thread message reference (e.g., 0.1)
        parts = str(email_ref).split('.')
        thread_idx = int(parts[0])
        msg_idx = int(parts[1])
        
        ensure(thread_idx in idx_to_email, f"Invalid thread number. Choose between 0 and {len(idx_to_email) - 1}")
        
        # Find the thread for this index
        email_data = idx_to_email[thread_idx]
        thread_id = None
        thread_messages = []
        
        for tid, messages in threads.items():
            if any(m['message_id'] == email_data['message_id'] for m in messages):
                thread_id = tid
                thread_messages = messages
                break
        
        ensure(thread_messages, "No thread found for this email")
        ensure(0 <= msg_idx < len(thread_messages), f"Invalid message index. Choose between 0 and {len(thread_messages) - 1}")
        
        # Delete specific message from thread
        msg = thread_messages[-(msg_idx + 1)]  # Reverse index
        emails_to_delete.append(msg['id'])
        
        print(f"Deleting message: {msg['subject']} from {msg['from']}")
        
    else:
        # Simple email/thread reference (e.g., 0)
        email_number = int(email_ref)
        ensure(email_number in idx_to_email, f"Invalid email number. Choose between 0 and {len(idx_to_email) - 1}")
        
        email_data = idx_to_email[email_number]
        
        # Check if this is part of a thread
        thread_id = None
        thread_messages = []
        
        for tid, messages in threads.items():
            if any(m['message_id'] == email_data['message_id'] for m in messages):
                thread_id = tid
                thread_messages = messages
                break
        
        if len(thread_messages) > 1:
            # Delete entire thread
            emails_to_delete.extend([msg['id'] for msg in thread_messages])
            print(f"Deleting thread: {email_data['subject']} ({len(thread_messages)} messages)")
        else:
            # Delete single email
            emails_to_delete.append(email_data['id'])
            print(f"Deleting email: {email_data['subject']} from {email_data['from']}")
    
    # Confirm deletion
    response = input(f"\n{Colors.YELLOW}Are you sure? (y/N): {Colors.ENDC}")
    if response.lower() != 'y':
        print("Cancelled.")
        return
    
    # Delete emails
    deleted_count = delete_emails(emails_to_delete)
    
    if deleted_count > 0:
        print(f"{Colors.GREEN}✓ Deleted {deleted_count} message(s){Colors.ENDC}")
        # Clear cache to force refresh
        CACHE_PATH.unlink(missing_ok=True)
    else:
        print(f"{Colors.RED}Failed to delete messages{Colors.ENDC}")

def reply_email(email_ref, body):
    """Reply to a specific email or thread message"""
    # Load from cache
    cache_data = load_cache()
    ensure(cache_data, "No cached email data found. Run 'smail' first to fetch emails.")
    
    idx_to_email = cache_data['idx_mapping']
    emails_data = cache_data['emails']
    threads = {}
    for thread_id, email_ids in cache_data['threads'].items():
        thread_emails = []
        for email_id in email_ids:
            for e in emails_data:
                if e['id'] == email_id:
                    thread_emails.append(e)
                    break
        if thread_emails:
            threads[thread_id] = thread_emails
    
    # Parse email reference (e.g., "0", "0.1", or "0.last")
    if '.' in str(email_ref):
        # Thread message reference
        parts = str(email_ref).split('.')
        thread_idx = int(parts[0])
        
        ensure(thread_idx in idx_to_email, f"Invalid thread number. Choose between 0 and {len(idx_to_email) - 1}")
        
        # Find the thread for this index
        thread_email_data = idx_to_email[thread_idx]
        thread_id = None
        thread_messages = []
        
        for tid, messages in threads.items():
            if any(m['message_id'] == thread_email_data['message_id'] for m in messages):
                thread_id = tid
                thread_messages = messages
                break
        
        ensure(thread_messages, "No thread found for this email")
        
        # Handle .last shortcut
        if parts[1] == "last":
            # Get the newest message in the thread (last in the list)
            email_data = thread_messages[-1]
        else:
            msg_idx = int(parts[1])
            ensure(0 <= msg_idx < len(thread_messages), f"Invalid message index. Choose between 0 and {len(thread_messages) - 1}")
            # Get specific message from thread (0 is newest)
            email_data = thread_messages[-(msg_idx + 1)]
    else:
        # Simple email reference
        email_number = int(email_ref)
        ensure(email_number in idx_to_email, f"Invalid email number. Choose between 0 and {len(idx_to_email) - 1}")
        email_data = idx_to_email[email_number]
    
    # Determine recipient
    from_full = email_data.get('from_full', email_data['from'])
    
    # Extract email address from full address
    if '<' in from_full:
        recipient = from_full.split('<')[1].split('>')[0]
    else:
        recipient = from_full
    
    # If we sent this email, we need to reply to ourselves for testing
    # In a real scenario, you'd parse the To: field from the original
    if recipient == EMAIL or recipient == LOGIN:
        # For now, reply to ourselves
        recipient = EMAIL
    
    # Prepare subject
    subject = email_data['subject']
    if not subject.lower().startswith('re: '):
        subject = 'Re: ' + subject
    
    # Send threaded reply
    message_id = email_data.get('message_id', '')
    send_email(recipient, subject, body, in_reply_to=message_id)
    
    print(f"{Colors.DIM}Replying to: {email_data['from']}{Colors.ENDC}")

def main():
    """Main entry point"""
    if len(sys.argv) == 1:
        # Default: list emails
        list_emails()
    elif sys.argv[1] == "send":
        if len(sys.argv) == 4:
            # smail send "subject" "body" - send to btmask
            send_email(EMAIL, sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 5:
            # smail send recipient "subject" "body"
            send_email(sys.argv[2], sys.argv[3], sys.argv[4])
        else:
            print(f"{Colors.YELLOW}Usage:{Colors.ENDC}")
            print("  smail send \"subject\" \"body\"")
            print("  smail send recipient@email.com \"subject\" \"body\"")
            sys.exit(1)
    elif len(sys.argv) == 4 and sys.argv[2] == "reply":
        # smail 0 reply "body" or smail 0.1 reply "body" or smail 0.last reply "body"
        email_ref = sys.argv[1]
        if email_ref.replace('.', '').isdigit() or email_ref.endswith('.last'):
            reply_email(email_ref, sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[2] == "delete":
        # smail 0 delete or smail 0.1 delete
        email_ref = sys.argv[1]
        if email_ref.replace('.', '').isdigit():
            delete_email(email_ref)
    elif sys.argv[1] == "delete" and len(sys.argv) == 3:
        # smail delete 0 or smail delete 0.1 - alternative syntax
        delete_email(sys.argv[2])
    elif sys.argv[1].replace('.', '').isdigit():
        # smail 1 or smail 0.1 - read email/thread by number
        read_email(sys.argv[1])
    elif sys.argv[1] == "read" and len(sys.argv) == 3:
        # smail read 1 or smail read 0.1 - alternative syntax
        read_email(sys.argv[2])
    else:
        print(f"{Colors.YELLOW}Usage:{Colors.ENDC}")
        print("  smail                     # List emails")
        print("  smail 0                   # Read email/thread #0")
        print("  smail 0.1                 # Read message #1 in thread #0")
        print("  smail 0 reply \"body\"     # Reply to email #0")
        print("  smail 0.last reply \"body\" # Reply to newest message in thread #0")
        print("  smail 0 delete            # Delete email/thread #0")
        print("  smail 0.1 delete          # Delete message #1 in thread #0")
        print("  smail send \"subject\" \"body\"")
        print("  smail send recipient@email.com \"subject\" \"body\"")
        sys.exit(1)

if __name__ == "__main__":
    main()