#!/usr/bin/env python3
"""smail - Simple email client for iCloud (v2 with clean data model)"""

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
import traceback
import inspect
import re
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.table import Table
from rich.prompt import Prompt
from rich.rule import Rule
from rich.padding import Padding
from rich.box import SIMPLE

# Global console instance
console = Console()

# Minimal beautiful assert with same API as assert
def ensure(condition, message=""):
    if not condition:
        
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
        match = re.search(r'ensure\((.*?),', source_line)
        condition_str = match.group(1) if match else source_line
        
        # Print beautiful error
        console.print(f"\n[dim]{short_filename}:{line_number}[/dim]")
        console.print(f"  [red]{condition_str}[/red]")
        console.print(f"  [red]↳[/red] {message if message else 'assertion failed'}\n")
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
    """Load display items from cache"""
    if not CACHE_PATH.exists():
        return None
    
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except Exception:
        return None

# Load config
CONFIG_PATH = Path.home() / ".config" / "smail" / "config.toml"

def load_config():
    """Load configuration or guide through setup"""
    if not CONFIG_PATH.exists():
        console.print("[yellow]Setting up smail...[/yellow]\n")
        
        # Get email
        email_addr = Prompt.ask("Enter your iCloud email")
        ensure(email_addr, "Email cannot be empty")
        ensure("@" in email_addr, "Invalid email format")
        
        # Get Apple ID if different
        console.print("\n[dim]Your Apple ID login might be different from your email.[/dim]")
        console.print("[dim]For example: email is john@icloud.com but login is john.doe@icloud.com[/dim]")
        login = Prompt.ask("\nApple ID login (press Enter if same as email)", default=email_addr)
        
        # Get keychain service name
        console.print("\n[dim]smail uses macOS Keychain to store your app-specific password.[/dim]")
        console.print("[dim]Choose a unique name for this keychain entry.[/dim]")
        keychain = Prompt.ask("\nKeychain service name", default="smail-icloud")
        
        # Get display name
        console.print("\n[dim]Your display name appears in emails you send.[/dim]")
        name = Prompt.ask("\nDisplay name (optional)", default="")
        
        # Save config
        config = f"""email = "{email_addr}"
login = "{login}"
keychain = "{keychain}"
"""
        if name:
            config += f'name = "{name}"\n'
        
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(config)
        
        console.print(f"\n[green]✓ Config saved to {CONFIG_PATH}[/green]")
        
        # Guide to add password
        console.print(f"\n[yellow]Next steps:[/yellow]")
        console.print("1. Get an app-specific password from:")
        console.print(f"   [cyan]https://appleid.apple.com[/cyan] → Sign-In and Security → App-Specific Passwords")
        console.print("\n2. Add it to your keychain:")
        console.print(f"   [bold]security add-generic-password -a \"{login}\" -s \"{keychain}\" -w[/bold]")
        console.print("\n3. Run smail again!")
        sys.exit(0)
    
    with open(CONFIG_PATH, 'rb') as f:
        return tomllib.load(f)

# Load configuration
config = load_config()
EMAIL = config['email']
LOGIN = config.get('login', EMAIL)
KEYCHAIN_SERVICE = config.get('keychain', 'smail-icloud')
NAME = config.get('name', '')

def get_password():
    """Get password from macOS keychain"""
    result = subprocess.run(
        ['security', 'find-generic-password', '-a', LOGIN, '-s', KEYCHAIN_SERVICE, '-w'],
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

def build_thread_index_map(messages):
    """Build a map of message_id to thread index based on latest-first numbering"""
    # Build parent-child relationships
    id_to_msg = {m['message_id']: m for m in messages}
    children_map = {}  # parent_id -> [child_messages]
    
    for msg in messages:
        parent_id = msg.get('in_reply_to', '')
        if parent_id and parent_id in id_to_msg:
            if parent_id not in children_map:
                children_map[parent_id] = []
            children_map[parent_id].append(msg)
    
    # Sort children by date (newest first)
    for parent_id in children_map:
        children_map[parent_id].sort(
            key=lambda x: parsedate_to_datetime(x['date']), 
            reverse=True
        )
    
    # Find the absolute newest message in the thread
    newest_msg = max(messages, key=lambda x: parsedate_to_datetime(x['date']))
    
    # Build the index map
    index_map = {}
    
    def assign_indices(msg, parent_path=[]):
        """Recursively assign indices with newest message getting .0 path"""
        msg_id = msg['message_id']
        
        # Get children sorted by date (newest first)
        children = children_map.get(msg_id, [])
        
        # Check if any descendant is the newest message
        def has_newest_descendant(m):
            if m['message_id'] == newest_msg['message_id']:
                return True
            for child in children_map.get(m['message_id'], []):
                if has_newest_descendant(child):
                    return True
            return False
        
        # Assign indices to children
        for i, child in enumerate(children):
            if has_newest_descendant(child):
                # This branch contains the newest message, gets .0
                child_path = parent_path + [0]
            else:
                # Other branches numbered by recency
                child_path = parent_path + [i if has_newest_descendant(children[0]) else i + 1]
            
            index_map[child['message_id']] = child_path
            assign_indices(child, child_path)
    
    # Find root message(s)
    roots = [m for m in messages if not m.get('in_reply_to') or m['in_reply_to'] not in id_to_msg]
    
    # Assign index to root
    for root in roots:
        index_map[root['message_id']] = []  # Root has empty path (displays as "0")
        assign_indices(root, [])
    
    return index_map

def build_display_items(emails):
    """Build display items with thread grouping"""
    # Map message IDs to emails
    id_to_email = {e['message_id']: e for e in emails}
    
    def find_root(msg_id, visited=None):
        """Find the root message of a thread"""
        if visited is None:
            visited = set()
        
        if msg_id in visited:
            return msg_id
        
        visited.add(msg_id)
        
        if msg_id not in id_to_email:
            return msg_id
        
        msg = id_to_email[msg_id]
        if not msg['in_reply_to']:
            return msg_id
        
        return find_root(msg['in_reply_to'], visited)
    
    # Group by thread root
    threads = {}
    for email in emails:
        root_id = find_root(email['message_id'])
        if root_id not in threads:
            threads[root_id] = []
        threads[root_id].append(email)
    
    # Build display items
    display_items = []
    seen_messages = set()
    
    for email in emails:
        if email['message_id'] in seen_messages:
            continue
            
        root_id = find_root(email['message_id'])
        thread_messages = threads[root_id]
        
        if len(thread_messages) > 1:
            # Build thread indices for this thread
            thread_indices = build_thread_index_map(thread_messages)
            
            # Thread
            display_items.append({
                "type": "thread",
                "messages": thread_messages,
                "thread_indices": thread_indices
            })
            for msg in thread_messages:
                seen_messages.add(msg['message_id'])
        else:
            # Single message
            display_items.append({
                "type": "single",
                "message": email
            })
            seen_messages.add(email['message_id'])
    
    return display_items

def list_emails(max_emails=20, from_cache=False):
    """List emails with clean display"""
    if from_cache:
        cache_data = load_cache()
        ensure(cache_data, "No cached email data found. Run 'smail' first to fetch emails.")
        display_items = cache_data['display_items']
    else:
        # Fetch fresh emails
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
            console.print("[dim]No emails found[/dim]")
            return
        
        # Fetch all emails
        emails_data = []
        
        for email_id in email_ids:
            # email_id might be bytes
            if isinstance(email_id, bytes):
                email_id = email_id.decode()
            
            # Fetch email body and flags
            typ, msg_data = mail.fetch(email_id, '(FLAGS BODY.PEEK[])')
            ensure(typ == 'OK', f"IMAP fetch failed: {typ}")
            ensure(msg_data, "No message data returned")
            
            # Parse FLAGS and BODY from response
            flags = []
            raw_email = None
            
            if isinstance(msg_data[0], tuple) and len(msg_data[0]) == 2:
                response_line = msg_data[0][0].decode() if isinstance(msg_data[0][0], bytes) else msg_data[0][0]
                
                # Extract flags
                if 'FLAGS' in response_line:
                    flags_match = re.search(r'FLAGS \(([^)]*)\)', response_line)
                    if flags_match:
                        flags = flags_match.group(1).split()
                
                raw_email = msg_data[0][1]
            else:
                raw_email = msg_data[0] if isinstance(msg_data[0], bytes) else msg_data[0][1]
            
            ensure(isinstance(raw_email, bytes), f"Expected bytes for email body")
            
            msg = email.message_from_bytes(raw_email)
            
            # Extract headers
            subject = decode_mime_string(msg.get('Subject') or 'No Subject')
            from_addr = decode_mime_string(msg.get('From') or 'Unknown')
            date = msg.get('Date')
            message_id = msg.get('Message-ID', '').strip('<>')
            in_reply_to = msg.get('In-Reply-To', '').strip('<>')
            references = msg.get('References', '')
            
            ensure(date, f"Email {email_id} has no date")
            
            # Clean up from address
            if '<' in from_addr:
                display_name = from_addr.split('<')[0].strip()
                email_addr = from_addr.split('<')[1].split('>')[0]
                if display_name and display_name != email_addr:
                    from_name = display_name
                else:
                    from_name = email_addr
            else:
                from_name = from_addr
            
            # Extract body
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
                'from_full': from_addr,
                'date': date,
                'message_id': message_id,
                'in_reply_to': in_reply_to,
                'references': references,
                'body': body,
                'is_read': '\\Seen' in flags
            })
        
        mail.close()
        mail.logout()
        
        # Build display items
        display_items = build_display_items(emails_data)
        
        # Save to cache
        save_cache(display_items)
    
    # Display emails using Rich Table
    table = Table(show_header=True, header_style="bold", box=SIMPLE, padding=(0, 1), expand=True)
    table.add_column("ID", width=6, no_wrap=True)
    table.add_column("Subject", width=40, no_wrap=True, overflow="ellipsis")
    table.add_column("From", style="cyan", no_wrap=True, overflow="ellipsis")
    table.add_column("Date", width=12, no_wrap=True)
    
    for idx, item in enumerate(display_items):
        if item['type'] == 'thread':
            messages = item['messages']
            latest = messages[-1]
            
            # Clean subject
            subject = latest['subject']
            if subject.lower().startswith('re: '):
                subject = subject[4:]
            
            # Add thread count
            subject = f"{subject} ({len(messages)})"
            
            # Get from name - use from_full if available
            from_full = latest.get('from_full', latest['from'])
            from_name = latest['from']
            
            # Show email in parentheses if we have a display name
            if from_name != from_full and '(' not in from_name:
                # Extract email from from_full
                if '<' in from_full:
                    email_part = from_full.split('<')[1].split('>')[0]
                    from_name = f"{from_name} ({email_part})"
            
            
            # Check if any unread
            has_unread = any(not m.get('is_read', True) for m in messages)
            
            # Format date
            date_str = format_date(latest['date'])
            
            # Build row with appropriate styling
            id_col = f"● {idx}" if has_unread else f"  {idx}"
            
            if has_unread:
                table.add_row(
                    id_col,
                    subject,
                    from_name,
                    date_str,
                    style="bold"
                )
            else:
                table.add_row(
                    id_col,
                    subject,
                    from_name,
                    date_str,
                    style="dim"
                )
        else:
            # Single message
            msg = item['message']
            
            # Clean subject
            subject = msg['subject']
            if subject.lower().startswith('re: '):
                subject = subject[4:]
            
            
            # Get from name - use from_full if available
            from_full = msg.get('from_full', msg['from'])
            from_name = msg['from']
            
            # Show email in parentheses if we have a display name
            if from_name != from_full and '(' not in from_name:
                # Extract email from from_full
                if '<' in from_full:
                    email_part = from_full.split('<')[1].split('>')[0]
                    from_name = f"{from_name} ({email_part})"
            
            
            # Format date
            date_str = format_date(msg['date'])
            
            # Build row with appropriate styling
            is_unread = not msg.get('is_read', True)
            id_col = f"● {idx}" if is_unread else f"  {idx}"
            
            if is_unread:
                table.add_row(
                    id_col,
                    subject,
                    from_name,
                    date_str,
                    style="bold"
                )
            else:
                table.add_row(
                    id_col,
                    subject,
                    from_name,
                    date_str,
                    style="dim"
                )
    
    console.print()
    console.print(table)

def read_email(index):
    """Read a specific email or thread"""
    cache_data = load_cache()
    ensure(cache_data, "No cached email data found. Run 'smail' first to fetch emails.")
    
    display_items = cache_data['display_items']
    ensure(0 <= index < len(display_items), f"Invalid index. Choose between 0 and {len(display_items) - 1}")
    
    item = display_items[index]
    
    if item['type'] == 'thread':
        # Display thread
        messages = item['messages']
        thread_indices = item.get('thread_indices', {})
        
        # Build thread tree for proper parent-child relationships
        id_to_msg = {m['message_id']: m for m in messages}
        roots = []
        
        for msg in messages:
            if not msg['in_reply_to'] or msg['in_reply_to'] not in id_to_msg:
                roots.append(msg)
        
        def format_thread_path(msg):
            """Format the thread path using computed indices"""
            path = thread_indices.get(msg['message_id'], [])
            if not path:
                return str(index)  # Root message shows as just the index
            return f"{index}.{'.'.join(map(str, path))}"
        
        def build_tree(msg, depth=0):
            # Find children
            children = [m for m in messages if m['in_reply_to'] == msg['message_id']]
            # Sort children by their thread index so .0 appears last (bottom)
            children.sort(key=lambda m: thread_indices.get(m['message_id'], []))
            
            # Render this message with proper thread path
            thread_ref = format_thread_path(msg)
            render_message_panel(msg, thread_ref, depth, console)
            
            # Render children - reversed so newest (.0) appears at bottom
            for child in reversed(children):
                build_tree(child, depth + 1)
        
        console.print()
        for root in roots:
            build_tree(root)
    else:
        # Display single message
        msg = item['message']
        console.print()
        console.print(f"{msg['subject']} [dim]·[/dim] [dim cyan]{msg['from']}[/dim cyan] [dim]·[/dim] [dim]{format_date(msg['date'])}[/dim]")
        console.print(Rule(style="dim"))
        console.print()
        console.print(msg['body'])
    
    # Mark messages as read
    emails_to_mark = []
    if item['type'] == 'thread':
        emails_to_mark = [m['id'] for m in item['messages'] if not m.get('is_read', True)]
    else:
        if not item['message'].get('is_read', True):
            emails_to_mark = [item['message']['id']]
    
    if emails_to_mark:
        mark_emails_as_read(emails_to_mark)
        
        # Update cache
        if item['type'] == 'thread':
            for msg in item['messages']:
                if msg['id'] in emails_to_mark:
                    msg['is_read'] = True
        else:
            item['message']['is_read'] = True
        
        save_cache(display_items)

def render_message_panel(msg, thread_ref, depth, console):
    """Render a message as a Rich panel"""
    content = Text()
    
    is_unread = not msg.get('is_read', True)
    
    if is_unread:
        content.append(f"{msg['subject']} · ", style="bold")
        content.append(msg['from'], style="bold cyan")
        content.append(f" · {format_date(msg['date'])}", style="bold")
    else:
        content.append(f"{msg['subject']} · ", style="bold")
        content.append(msg['from'], style="cyan")
        content.append(f" · {format_date(msg['date'])}", style="dim")
    
    content.append("\n")
    content.append("─" * 72, style="bright_black")
    content.append("\n")
    content.append(msg['body'].strip())
    
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
    
    if depth > 0:
        padded = Padding(panel, (0, 0, 0, depth * 2))
        console.print(padded)
    else:
        console.print(panel)

def mark_emails_as_read(email_ids):
    """Mark emails as read in IMAP"""
    password = get_password()
    
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(LOGIN, password)
    mail.select('INBOX')
    
    for email_id in email_ids:
        try:
            mail.store(email_id, '+FLAGS', '\\Seen')
        except Exception as e:
            console.print(f"[yellow]Warning: Could not mark email {email_id} as read: {e}[/yellow]")
    
    mail.close()
    mail.logout()

def delete_emails(email_ids):
    """Delete emails from IMAP"""
    password = get_password()
    
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
            console.print(f"[yellow]Warning: Could not delete email {email_id}: {e}[/yellow]")
    
    # Expunge to permanently delete
    mail.expunge()
    mail.close()
    mail.logout()
    
    return deleted_count

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
    
    # Connect to SMTP server
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(LOGIN, password)
    
    # Send email
    server.send_message(msg)
    server.quit()
    
    console.print(f"[green]✓ Email sent to {recipient}[/green]")

def parse_index(index_str):
    """Parse index string like '0', '0.1', '0.last' into structured format"""
    parts = index_str.split('.')
    parsed = []
    
    for part in parts:
        if part in ['last', 'latest']:
            parsed.append('last')  # Normalize both to 'last'
        elif part.isdigit():
            parsed.append(int(part))
        else:
            raise ValueError(f"Invalid index part: {part}")
    
    return parsed

def resolve_index(parsed_index, display_items):
    """Resolve parsed index to actual message data"""
    if not parsed_index:
        raise ValueError("Empty index")
    
    # Get the main item
    main_idx = parsed_index[0]
    if main_idx >= len(display_items):
        raise ValueError(f"Index {main_idx} out of range (0-{len(display_items)-1})")
    
    item = display_items[main_idx]
    
    # If no sub-index, return the whole item
    if len(parsed_index) == 1:
        return {
            'type': 'item',
            'data': item,
            'index': main_idx
        }
    
    # Handle thread navigation
    if item['type'] != 'thread':
        raise ValueError(f"Item {main_idx} is not a thread")
    
    messages = item['messages']
    thread_indices = item.get('thread_indices', {})
    
    # Build reverse map: path -> message
    path_to_msg = {}
    for msg in messages:
        msg_id = msg['message_id']
        path = thread_indices.get(msg_id, [])
        if not path:  # Root message
            path_to_msg[tuple()] = msg
        else:
            path_to_msg[tuple(path)] = msg
    
    # Convert parsed index to path (skip the main index)
    search_path = []
    for part in parsed_index[1:]:
        if part == 'last':
            # Find the message with the longest path at this level
            candidates = [p for p in path_to_msg.keys() if len(p) == len(search_path) + 1 and p[:len(search_path)] == tuple(search_path)]
            if not candidates:
                raise ValueError(f"No messages at path {'.'.join(map(str, parsed_index))}")
            # Get the one with index 0 (newest)
            search_path.append(0)
        else:
            search_path.append(part)
    
    # Find the message
    target_path = tuple(search_path)
    if target_path not in path_to_msg:
        raise ValueError(f"No message at path {'.'.join(map(str, parsed_index))}")
    
    return {
        'type': 'message',
        'data': path_to_msg[target_path],
        'thread': item,
        'index_str': '.'.join(map(str, parsed_index))
    }

def parse_arguments(args):
    """Parse command line arguments into structured format"""
    if not args:
        return {'action': 'list'}
    
    # Check if first arg looks like an index
    first_arg = args[0]
    
    # Check if first arg is an email address
    if '@' in first_arg:
        # Email pattern: <email> <subject> <body>
        if len(args) >= 3:
            return {
                'action': 'send',
                'recipient': first_arg,
                'subject': args[1],
                'body': ' '.join(args[2:])
            }
        else:
            return {
                'action': 'error',
                'message': f"Invalid email syntax. Usage: smail <email> <subject> <body>"
            }
    
    # Check if it's just two strings (send to self)
    if len(args) >= 2 and not any(arg in ['reply', 'delete', 'help', 'compose'] for arg in args):
        # Check if first arg is not an index
        try:
            parse_index(first_arg)
        except ValueError:
            # Not an index, treat as subject for self-email
            return {
                'action': 'send',
                'recipient': EMAIL,  # Send to self
                'subject': args[0],
                'body': ' '.join(args[1:])
            }
    
    # Actions that don't require an index
    standalone_actions = ['reply', 'compose', 'help']
    if first_arg in standalone_actions:
        return {
            'action': first_arg,
            'args': args[1:]
        }
    
    # Try to parse as index
    try:
        parsed_index = parse_index(first_arg)
        
        # Check for action after index
        if len(args) > 1:
            action = args[1]
            action_args = args[2:]
            return {
                'action': action,
                'index': parsed_index,
                'index_str': first_arg,
                'args': action_args
            }
        else:
            # Default action is read
            return {
                'action': 'read',
                'index': parsed_index,
                'index_str': first_arg
            }
    except ValueError:
        # Not a valid index, might be an unknown command
        return {
            'action': 'error',
            'message': f"Unknown command: {first_arg}"
        }

def main():
    """Main entry point"""
    args = sys.argv[1:]
    
    try:
        parsed = parse_arguments(args)
        
        match parsed['action']:
            case 'list':
                list_emails()
            
            case 'read':
                # Load cache to resolve index
                cache_data = load_cache()
                if not cache_data:
                    console.print("[red]No cached email data. Run 'smail' first.[/red]")
                    return
                
                resolved = resolve_index(parsed['index'], cache_data['display_items'])
                
                if resolved['type'] == 'item':
                    # Reading a whole item (thread or single message)
                    read_email(resolved['index'])
                else:
                    # Reading a specific message in a thread
                    msg = resolved['data']
                    console.print()
                    render_message_panel(msg, resolved['index_str'], 0, console)
            
            case 'send':
                send_email(parsed['recipient'], parsed['subject'], parsed['body'])
            
            case 'delete':
                if 'index' not in parsed:
                    console.print("[red]Error: Delete requires an index[/red]")
                    console.print("Usage: smail <index> delete")
                    return
                
                # Load cache to resolve index
                cache_data = load_cache()
                if not cache_data:
                    console.print("[red]No cached email data. Run 'smail' first.[/red]")
                    return
                
                try:
                    resolved = resolve_index(parsed['index'], cache_data['display_items'])
                    display_items = cache_data['display_items']
                    
                    # Collect emails to delete
                    emails_to_delete = []
                    
                    if resolved['type'] == 'item':
                        item = resolved['data']
                        if item['type'] == 'thread':
                            # Delete entire thread
                            messages = item['messages']
                            for msg in messages:
                                emails_to_delete.append(msg['id'])
                            console.print(f"Deleting thread: {messages[0]['subject']} ({len(messages)} messages)")
                        else:
                            # Delete single message
                            msg = item['message']
                            emails_to_delete.append(msg['id'])
                            console.print(f"Deleting message: {msg['subject']} from {msg['from']}")
                    else:
                        # Delete specific message in thread
                        msg = resolved['data']
                        emails_to_delete.append(msg['id'])
                        console.print(f"Deleting message: {msg['subject']} from {msg['from']}")
                    
                    # Confirm deletion
                    if len(emails_to_delete) > 1:
                        confirm = Prompt.ask(f"\nDelete {len(emails_to_delete)} messages?", choices=["y", "n"], default="n")
                    else:
                        confirm = Prompt.ask("\nDelete this message?", choices=["y", "n"], default="n")
                    
                    if confirm == "y":
                        deleted_count = delete_emails(emails_to_delete)
                        console.print(f"[green]✓ Deleted {deleted_count} message(s)[/green]")
                        
                        # Update cache by removing deleted items
                        # For now, just clear cache so next list will refresh
                        CACHE_PATH.unlink(missing_ok=True)
                        console.print("[dim]Cache cleared. Run 'smail' to refresh.[/dim]")
                    else:
                        console.print("[yellow]Deletion cancelled[/yellow]")
                        
                except ValueError as e:
                    console.print(f"[red]Error: {e}[/red]")
            
            case 'reply':
                if 'index' in parsed:
                    # Reply to specific message
                    cache_data = load_cache()
                    if not cache_data:
                        console.print("[red]No cached email data. Run 'smail' first.[/red]")
                        return
                    
                    try:
                        resolved = resolve_index(parsed['index'], cache_data['display_items'])
                        
                        # Get the message to reply to
                        if resolved['type'] == 'item':
                            item = resolved['data']
                            if item['type'] == 'thread':
                                # Reply to latest message in thread
                                msg = item['messages'][-1]
                            else:
                                # Reply to single message
                                msg = item['message']
                        else:
                            # Reply to specific message in thread
                            msg = resolved['data']
                        
                        # Determine recipient
                        from_full = msg.get('from_full', msg['from'])
                        
                        # Extract email address from full address
                        if '<' in from_full:
                            recipient = from_full.split('<')[1].split('>')[0]
                        else:
                            recipient = from_full
                        
                        # If we sent this email, reply to ourselves
                        if recipient == EMAIL or recipient == LOGIN:
                            recipient = EMAIL
                        
                        # Prepare subject
                        subject = msg['subject']
                        if not subject.lower().startswith('re: '):
                            subject = 'Re: ' + subject
                        
                        # Get body from args or use empty
                        body = ' '.join(parsed.get('args', []))
                        if not body:
                            console.print("[red]Error: Reply body is required[/red]")
                            return
                        
                        # Send threaded reply
                        message_id = msg.get('message_id', '')
                        send_email(recipient, subject, body, in_reply_to=message_id)
                        
                        console.print(f"[dim]Replied to: {msg['from']}[/dim]")
                        
                    except ValueError as e:
                        console.print(f"[red]Error: {e}[/red]")
                else:
                    # Reply to latest email
                    cache_data = load_cache()
                    if not cache_data:
                        console.print("[red]No cached email data. Run 'smail' first.[/red]")
                        return
                    
                    display_items = cache_data['display_items']
                    if not display_items:
                        console.print("[red]No emails to reply to[/red]")
                        return
                    
                    # Get the latest item (first in list)
                    latest_item = display_items[0]
                    
                    if latest_item['type'] == 'thread':
                        # Get the absolute newest message across all threads
                        all_messages = []
                        for item in display_items:
                            if item['type'] == 'thread':
                                all_messages.extend(item['messages'])
                            else:
                                all_messages.append(item['message'])
                        
                        # Find newest message by date
                        msg = max(all_messages, key=lambda m: parsedate_to_datetime(m['date']))
                    else:
                        msg = latest_item['message']
                    
                    # Determine recipient
                    from_full = msg.get('from_full', msg['from'])
                    
                    # Extract email address from full address
                    if '<' in from_full:
                        recipient = from_full.split('<')[1].split('>')[0]
                    else:
                        recipient = from_full
                    
                    # If we sent this email, reply to ourselves
                    if recipient == EMAIL or recipient == LOGIN:
                        recipient = EMAIL
                    
                    # Prepare subject
                    subject = msg['subject']
                    if not subject.lower().startswith('re: '):
                        subject = 'Re: ' + subject
                    
                    # Get body from args
                    body = ' '.join(parsed.get('args', []))
                    if not body:
                        console.print("[red]Error: Reply body is required[/red]")
                        console.print("Usage: smail reply <body>")
                        return
                    
                    # Send threaded reply
                    message_id = msg.get('message_id', '')
                    send_email(recipient, subject, body, in_reply_to=message_id)
                    
                    console.print(f"[dim]Replied to: {msg['from']}[/dim]")
            
            case 'compose':
                console.print("[yellow]Compose functionality not yet implemented[/yellow]")
            
            case 'help':
                console.print("[bold]smail - Simple email client for iCloud[/bold]\n")
                console.print("[bold]Usage:[/bold]")
                console.print("  smail                    List emails")
                console.print("  smail <index>            Read email/thread at index")
                console.print("  smail <index>.<sub>      Read specific message in thread")
                console.print("  smail <index>.last       Read last message in thread")
                console.print("  smail <index> delete     Delete email/thread")
                console.print("  smail <index> reply      Reply to email/thread")
                console.print("  smail reply              Reply to most recent email")
                console.print("  smail <subject> <body>   Send email to yourself")
                console.print("  smail <email> <subject> <body>  Send email to recipient")
            
            case 'error':
                console.print(f"[red]{parsed['message']}[/red]\n")
                # Show help directly
                console.print("[bold]Usage:[/bold]")
                console.print("  smail                    List emails")
                console.print("  smail <index>            Read email/thread at index")
                console.print("  smail <index>.<sub>      Read specific message in thread")
                console.print("  smail <index>.last       Read last message in thread")
                console.print("  smail <index> delete     Delete email/thread")
                console.print("  smail <index> reply      Reply to email/thread")
                console.print("  smail reply              Reply to most recent email")
                console.print("  smail <subject> <body>   Send email to yourself")
                console.print("  smail <email> <subject> <body>  Send email to recipient")
            
            case _:
                console.print(f"[red]Unknown action: {parsed['action']}[/red]\n")
                # Show help directly
                console.print("[bold]Usage:[/bold]")
                console.print("  smail                    List emails")
                console.print("  smail <index>            Read email/thread at index")
                console.print("  smail <index>.<sub>      Read specific message in thread")
                console.print("  smail <index>.last       Read last message in thread")
                console.print("  smail <index> delete     Delete email/thread")
                console.print("  smail <index> reply      Reply to email/thread")
                console.print("  smail reply              Reply to most recent email")
                console.print("  smail <subject> <body>   Send email to yourself")
                console.print("  smail <email> <subject> <body>  Send email to recipient")
                
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if '--debug' in args:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()