#!/usr/bin/env python3
"""
Security Log Redaction Tool
Fast, configurable script for sensitive data masking in security logs.
Supports streaming processing and flexible rule configuration.
"""

import os
import sys
import re
import json
import hmac
import hashlib
import argparse
import yaml
import time
import threading
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from typing import Dict, List, Any, Optional, Union, Tuple


class RedactionStats:
    """Statistics collection for redaction operations."""
    
    def __init__(self):
        self.lines_processed = 0
        self.redactions_applied = 0
        self.json_objects_processed = 0
        self.processing_time = 0.0
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def increment(self, lines=0, redactions=0, json_objects=0):
        with self.lock:
            self.lines_processed += lines
            self.redactions_applied += redactions
            self.json_objects_processed += json_objects
    
    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            elapsed = time.time() - self.start_time
            return {
                'lines_processed': self.lines_processed,
                'redactions_applied': self.redactions_applied,
                'json_objects_processed': self.json_objects_processed,
                'processing_time_seconds': elapsed,
                'lines_per_second': self.lines_processed / elapsed if elapsed > 0 else 0
            }


class LogRedactor:
    """Main log redaction engine with configurable rules."""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.salt = os.getenv(self.config.get('salt_env', ''), '')
        self.salt_version = self.config.get('salt_version', 'v1')
        self.max_line_len = int(self.config.get('max_line_len', 0) or 0)
        self.key_denylist = set(k.lower() for k in self.config.get('key_denylist', []))
        self.actions = self._compile_actions(self.config.get('actions', []))
        self.stats = RedactionStats()
        
        if not self.salt:
            print('[WARN] REDACT_SALT environment variable is empty; hashing will be weak.', 
                  file=sys.stderr)
    
    def _load_config(self, path: str) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ValueError(f"Failed to load config {path}: {e}")
    
    def _compile_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Pre-compile regex patterns for performance."""
        compiled = []
        for action in actions:
            action_copy = dict(action)
            if action.get('type') == 'regex':
                # Compile main patterns
                if 'patterns' in action:
                    action_copy['compiled_patterns'] = [
                        re.compile(p, re.IGNORECASE | re.MULTILINE) 
                        for p in action['patterns']
                    ]
                
                # Compile rule patterns
                if 'rules' in action:
                    for rule in action_copy['rules']:
                        if 'pattern' in rule:
                            rule['compiled'] = re.compile(
                                rule['pattern'], 
                                re.IGNORECASE | re.MULTILINE
                            )
            compiled.append(action_copy)
        return compiled
    
    def _hmac_hex(self, text: str, length: int = 16) -> str:
        """Generate HMAC-SHA256 hash with salt and version."""
        if not self.salt:
            return 'no_salt'
        
        versioned_text = f"{self.salt_version}:{text}"
        digest = hmac.new(
            self.salt.encode('utf-8'), 
            versioned_text.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()[:length]
        
        return f"{self.salt_version}:{digest}"
    
    def _redact_url_query(self, text: str, param_keys: List[str]) -> str:
        """Redact sensitive parameters in URLs."""
        if not param_keys:
            return text
        
        url_pattern = re.compile(r'((?:https?|wss?|ftp)://[^\s"\'<>]+)')
        key_set = set(k.lower() for k in param_keys)
        redactions = 0
        
        def replace_url(match):
            nonlocal redactions
            url = match.group(1)
            try:
                parsed = urlsplit(url)
                query_params = parse_qsl(parsed.query, keep_blank_values=True)
                fragment = parsed.fragment
                changed = False
                new_params = []
                
                for key, value in query_params:
                    if key.lower() in key_set and value:
                        hash_val = self._hmac_hex(value)
                        new_params.append((key, '***'))
                        fragment = (fragment + f'|h({key})={hash_val}') if fragment else f'h({key})={hash_val}'
                        changed = True
                        redactions += 1
                    else:
                        new_params.append((key, value))
                
                if changed:
                    new_parsed = parsed._replace(
                        query=urlencode(new_params), 
                        fragment=fragment
                    )
                    return match.group(0).replace(url, urlunsplit(new_parsed))
            except Exception:
                pass
            return match.group(0)
        
        result = url_pattern.sub(replace_url, text)
        self.stats.increment(redactions=redactions)
        return result
    
    def _redact_json_object(self, obj: Any, rules: List[Dict[str, Any]]) -> Any:
        """Recursively redact JSON objects based on key rules."""
        if isinstance(obj, dict):
            result = {}
            redactions = 0
            
            for key, value in obj.items():
                key_lower = str(key).lower()
                action = None
                
                # Check explicit rules first
                for rule in rules:
                    rule_keys = [str(k).lower() for k in rule.get('keys', [])]
                    if key_lower in rule_keys:
                        action = rule.get('action')
                        break
                
                # Check denylist if no explicit rule
                if not action and key_lower in self.key_denylist:
                    action = 'mask_and_hash'
                
                # Apply action
                if action == 'remove':
                    result[key] = '[REMOVED]'
                    redactions += 1
                elif action in ('mask', 'mask_and_hash', 'hash'):
                    str_value = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
                    if action == 'hash':
                        result[key] = f'/*h={self._hmac_hex(str_value)}*/'
                    elif action == 'mask_and_hash':
                        result[key] = f'***/*h={self._hmac_hex(str_value)}*/'
                    else:
                        result[key] = '***'
                    redactions += 1
                else:
                    result[key] = self._redact_json_object(value, rules)
            
            self.stats.increment(redactions=redactions)
            return result
        
        elif isinstance(obj, list):
            return [self._redact_json_object(item, rules) for item in obj]
        
        return obj
    
    def _mask_and_hash_pattern(self, text: str, pattern: re.Pattern) -> str:
        """Apply mask and hash replacement for regex patterns."""
        redactions = 0
        
        def replace_match(match):
            nonlocal redactions
            matched_text = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            
            # Special handling for IP addresses
            if ':' in matched_text and '.' not in matched_text:
                # IPv6
                parts = matched_text.split(':')
                masked = ':'.join(parts[:4] + ['xxxx'] * max(0, len(parts) - 4))
            elif '.' in matched_text and matched_text.count('.') == 3:
                # IPv4
                segments = matched_text.split('.')
                masked = '.'.join(segments[:3] + ['xxx']) if len(segments) == 4 else matched_text
            else:
                # Generic masking
                masked = '***'
            
            hash_suffix = f'/*h={self._hmac_hex(matched_text)}*/'
            redactions += 1
            return f'{masked}{hash_suffix}'
        
        result = pattern.sub(replace_match, text)
        self.stats.increment(redactions=redactions)
        return result
    
    def _apply_regex_action(self, text: str, action: Dict[str, Any]) -> str:
        """Apply regex-based redaction actions."""
        action_type = action.get('action')
        redactions = 0
        
        if action_type == 'remove':
            for pattern in action.get('compiled_patterns', []):
                text = pattern.sub('[REMOVED]', text)
                redactions += len(pattern.findall(text))
        
        elif action_type == 'mask':
            # Apply rule-based masking
            for rule in action.get('rules', []):
                if 'compiled' in rule:
                    replacement = rule.get('replacement', '***')
                    text = rule['compiled'].sub(replacement, text)
                    redactions += len(rule['compiled'].findall(text))
            
            # Apply pattern-based masking
            replacement = action.get('replacement')
            if replacement:
                for pattern in action.get('compiled_patterns', []):
                    text = pattern.sub(replacement, text)
                    redactions += len(pattern.findall(text))
        
        elif action_type == 'mask_and_hash':
            for pattern in action.get('compiled_patterns', []):
                text = self._mask_and_hash_pattern(text, pattern)
        
        self.stats.increment(redactions=redactions)
        return text
    
    def process_line(self, line: str) -> str:
        """Process a single log line through all redaction rules."""
        # Truncate oversized lines
        if self.max_line_len and len(line.encode('utf-8', 'ignore')) > self.max_line_len:
            line = line[:self.max_line_len] + '/*CLIPPED*/'
        
        result = line
        
        # Process URL query parameters first
        for action in self.actions:
            if (action.get('type') == 'regex' and 
                action.get('action') == 'replace_query_value'):
                result = self._redact_url_query(
                    result, 
                    action.get('url_param_keys', [])
                )
        
        # Try to parse as JSON
        json_obj = None
        is_json = False
        try:
            json_obj = json.loads(result)
            is_json = True
            self.stats.increment(json_objects=1)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Apply JSON key-based redaction
        if is_json and json_obj is not None:
            for action in self.actions:
                if action.get('type') == 'json_key':
                    json_obj = self._redact_json_object(
                        json_obj, 
                        action.get('rules', [])
                    )
            result = json.dumps(json_obj, ensure_ascii=False, separators=(',', ':'))
        
        # Apply regex-based actions
        for action in self.actions:
            if action.get('type') == 'regex' and action.get('action') != 'replace_query_value':
                result = self._apply_regex_action(result, action)
        
        self.stats.increment(lines=1)
        return result
    
    def process_stream(self, input_stream=None, output_stream=None):
        """Process log stream with optional progress reporting."""
        input_stream = input_stream or sys.stdin
        output_stream = output_stream or sys.stdout
        
        try:
            for line in input_stream:
                processed_line = self.process_line(line.rstrip('\n'))
                output_stream.write(processed_line + '\n')
                output_stream.flush()
        except KeyboardInterrupt:
            print('\n[INFO] Processing interrupted by user.', file=sys.stderr)
        except Exception as e:
            print(f'[ERROR] Processing failed: {e}', file=sys.stderr)
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return self.stats.get_stats()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Security Log Redaction Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  cat security.log | python redact.py --rules redaction-rules.yaml > clean.log
  
  # With statistics
  python redact.py --rules redaction-rules.yaml --stats < input.log > output.log
  
  # Process file directly
  python redact.py --rules redaction-rules.yaml --input security.log --output clean.log
        """
    )
    
    parser.add_argument(
        '--rules', 
        required=True, 
        help='Path to YAML configuration file'
    )
    parser.add_argument(
        '--input', 
        help='Input file (default: stdin)'
    )
    parser.add_argument(
        '--output', 
        help='Output file (default: stdout)'
    )
    parser.add_argument(
        '--stats', 
        action='store_true', 
        help='Print processing statistics to stderr'
    )
    parser.add_argument(
        '--validate-config', 
        action='store_true', 
        help='Validate configuration and exit'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize redactor
        redactor = LogRedactor(args.rules)
        
        # Validate configuration only
        if args.validate_config:
            print('[INFO] Configuration validation successful.', file=sys.stderr)
            return 0
        
        # Setup input/output streams
        input_stream = sys.stdin
        output_stream = sys.stdout
        
        if args.input:
            input_stream = open(args.input, 'r', encoding='utf-8')
        if args.output:
            output_stream = open(args.output, 'w', encoding='utf-8')
        
        try:
            # Process the stream
            redactor.process_stream(input_stream, output_stream)
            
            # Print statistics if requested
            if args.stats:
                stats = redactor.get_stats()
                print(f'[STATS] Processed {stats["lines_processed"]} lines, '
                      f'{stats["redactions_applied"]} redactions, '
                      f'{stats["lines_per_second"]:.1f} lines/sec', 
                      file=sys.stderr)
        
        finally:
            if args.input and input_stream != sys.stdin:
                input_stream.close()
            if args.output and output_stream != sys.stdout:
                output_stream.close()
        
        return 0
    
    except Exception as e:
        print(f'[ERROR] {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())