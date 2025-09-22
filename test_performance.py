#!/usr/bin/env python3
"""
Performance testing script for log redaction tool.
Generates test data and measures processing performance.
"""

import os
import sys
import time
import random
import string
import json
import subprocess
import tempfile
from typing import List, Dict, Any


class TestDataGenerator:
    """Generate realistic test log data for performance testing."""
    
    def __init__(self):
        self.domains = ['example.com', 'test.org', 'company.net', 'api.service.io']
        self.usernames = ['user123', 'admin', 'test_user', 'john.doe', 'api_client']
        self.ips = ['192.168.1.100', '10.0.0.50', '172.16.0.200', '203.0.113.42']
        self.phones = ['13812345678', '15987654321', '18666888999', '13511112222']
        self.emails = ['test@example.com', 'admin@company.net', 'user@domain.org']
        
    def random_string(self, length: int = 10) -> str:
        """Generate random alphanumeric string."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def random_token(self) -> str:
        """Generate random API token."""
        return self.random_string(32)
    
    def random_jwt(self) -> str:
        """Generate fake JWT token."""
        header = self.random_string(20)
        payload = self.random_string(50)
        signature = self.random_string(30)
        return f"{header}.{payload}.{signature}"
    
    def random_ip(self) -> str:
        """Get random IP address."""
        return random.choice(self.ips)
    
    def random_phone(self) -> str:
        """Get random Chinese phone number."""
        return random.choice(self.phones)
    
    def random_email(self) -> str:
        """Get random email address."""
        return random.choice(self.emails)
    
    def generate_json_log(self) -> str:
        """Generate a JSON log entry with sensitive data."""
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'level': random.choice(['INFO', 'WARN', 'ERROR']),
            'message': f'User action: {random.choice(["login", "logout", "api_call", "data_access"])}',
            'user_id': random.randint(1000, 9999),
            'ip': self.random_ip(),
            'user_agent': 'Mozilla/5.0 (compatible; TestBot/1.0)',
        }
        
        # Add sensitive data randomly
        if random.random() < 0.3:
            log_entry['access_token'] = self.random_token()
        if random.random() < 0.2:
            log_entry['phone'] = self.random_phone()
        if random.random() < 0.2:
            log_entry['email'] = self.random_email()
        if random.random() < 0.1:
            log_entry['password'] = 'secret123'
        if random.random() < 0.1:
            log_entry['api_key'] = f'AKIA{self.random_string(16).upper()}'
        
        return json.dumps(log_entry, ensure_ascii=False)
    
    def generate_text_log(self) -> str:
        """Generate a plain text log entry."""
        templates = [
            f'{time.strftime("%Y-%m-%d %H:%M:%S")} [INFO] User {random.choice(self.usernames)} logged in from {self.random_ip()}',
            f'{time.strftime("%Y-%m-%d %H:%M:%S")} [ERROR] Failed authentication for {self.random_email()}',
            f'{time.strftime("%Y-%m-%d %H:%M:%S")} [WARN] API rate limit exceeded for key: {self.random_token()}',
            f'{time.strftime("%Y-%m-%d %H:%M:%S")} [INFO] SMS sent to {self.random_phone()}',
            f'{time.strftime("%Y-%m-%d %H:%M:%S")} [DEBUG] JWT token: {self.random_jwt()}',
        ]
        return random.choice(templates)
    
    def generate_mixed_log(self) -> str:
        """Generate mixed format log entry."""
        if random.random() < 0.6:
            return self.generate_json_log()
        else:
            return self.generate_text_log()
    
    def generate_test_file(self, filename: str, num_lines: int, log_type: str = 'mixed'):
        """Generate test log file."""
        generators = {
            'json': self.generate_json_log,
            'text': self.generate_text_log,
            'mixed': self.generate_mixed_log
        }
        
        generator = generators.get(log_type, self.generate_mixed_log)
        
        with open(filename, 'w', encoding='utf-8') as f:
            for _ in range(num_lines):
                f.write(generator() + '\n')


class PerformanceTester:
    """Performance testing for redaction script."""
    
    def __init__(self, script_path: str, rules_path: str):
        self.script_path = script_path
        self.rules_path = rules_path
        self.generator = TestDataGenerator()
    
    def measure_processing_time(self, input_file: str) -> Dict[str, Any]:
        """Measure processing time and throughput."""
        # Get file size
        file_size_bytes = os.path.getsize(input_file)
        file_size_mb = file_size_bytes / (1024 * 1024)
        
        # Count lines
        with open(input_file, 'r') as f:
            line_count = sum(1 for _ in f)
        
        # Run redaction
        start_time = time.time()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_output:
            try:
                result = subprocess.run([
                    sys.executable, self.script_path,
                    '--rules', self.rules_path,
                    '--input', input_file,
                    '--output', temp_output.name,
                    '--stats'
                ], capture_output=True, text=True, timeout=300)
                
                end_time = time.time()
                processing_time = end_time - start_time
                
                if result.returncode != 0:
                    raise RuntimeError(f"Redaction failed: {result.stderr}")
                
                # Parse stats from stderr
                stats_line = None
                for line in result.stderr.split('\n'):
                    if '[STATS]' in line:
                        stats_line = line
                        break
                
                # Calculate metrics
                throughput_mb_s = file_size_mb / processing_time if processing_time > 0 else 0
                throughput_lines_s = line_count / processing_time if processing_time > 0 else 0
                
                return {
                    'file_size_mb': file_size_mb,
                    'line_count': line_count,
                    'processing_time_seconds': processing_time,
                    'throughput_mb_per_second': throughput_mb_s,
                    'throughput_lines_per_second': throughput_lines_s,
                    'stats_output': stats_line,
                    'success': True
                }
                
            finally:
                # Clean up temp file
                if os.path.exists(temp_output.name):
                    os.unlink(temp_output.name)
    
    def run_performance_tests(self) -> List[Dict[str, Any]]:
        """Run comprehensive performance tests."""
        test_cases = [
            {'name': 'Small JSON logs', 'lines': 1000, 'type': 'json'},
            {'name': 'Medium mixed logs', 'lines': 10000, 'type': 'mixed'},
            {'name': 'Large text logs', 'lines': 100000, 'type': 'text'},
            {'name': 'XL mixed logs', 'lines': 500000, 'type': 'mixed'},
        ]
        
        results = []
        
        for test_case in test_cases:
            print(f"Running test: {test_case['name']} ({test_case['lines']} lines)")
            
            # Generate test file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as temp_input:
                test_file = temp_input.name
            
            try:
                # Generate test data
                print(f"  Generating {test_case['lines']} lines of {test_case['type']} logs...")
                self.generator.generate_test_file(test_file, test_case['lines'], test_case['type'])
                
                # Run performance test
                print("  Processing...")
                result = self.measure_processing_time(test_file)
                result['test_case'] = test_case['name']
                result['log_type'] = test_case['type']
                results.append(result)
                
                # Print results
                if result['success']:
                    print(f"  ✓ Completed in {result['processing_time_seconds']:.2f}s")
                    print(f"    Throughput: {result['throughput_mb_per_second']:.1f} MB/s, "
                          f"{result['throughput_lines_per_second']:.0f} lines/s")
                else:
                    print(f"  ✗ Failed")
                
                print()
                
            finally:
                # Clean up test file
                if os.path.exists(test_file):
                    os.unlink(test_file)
        
        return results
    
    def generate_performance_report(self, results: List[Dict[str, Any]]):
        """Generate formatted performance report."""
        print("=" * 80)
        print("PERFORMANCE REPORT")
        print("=" * 80)
        print()
        
        print(f"{'Test Case':<25} {'Lines':<10} {'Size(MB)':<10} {'Time(s)':<10} {'MB/s':<10} {'Lines/s':<12}")
        print("-" * 80)
        
        for result in results:
            if result['success']:
                print(f"{result['test_case']:<25} "
                      f"{result['line_count']:<10} "
                      f"{result['file_size_mb']:<10.2f} "
                      f"{result['processing_time_seconds']:<10.2f} "
                      f"{result['throughput_mb_per_second']:<10.1f} "
                      f"{result['throughput_lines_per_second']:<12.0f}")
            else:
                print(f"{result['test_case']:<25} FAILED")
        
        print()
        
        # Summary statistics
        successful_results = [r for r in results if r['success']]
        if successful_results:
            avg_throughput_mb = sum(r['throughput_mb_per_second'] for r in successful_results) / len(successful_results)
            avg_throughput_lines = sum(r['throughput_lines_per_second'] for r in successful_results) / len(successful_results)
            
            print("SUMMARY:")
            print(f"  Average throughput: {avg_throughput_mb:.1f} MB/s, {avg_throughput_lines:.0f} lines/s")
            print(f"  Tests passed: {len(successful_results)}/{len(results)}")
        
        print()


def main():
    """Main performance testing entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Performance testing for log redaction tool')
    parser.add_argument('--script', default='redact.py', help='Path to redaction script')
    parser.add_argument('--rules', default='redaction-rules.yaml', help='Path to rules file')
    parser.add_argument('--generate-only', action='store_true', help='Only generate test data')
    parser.add_argument('--output', help='Test data output file')
    parser.add_argument('--lines', type=int, default=10000, help='Number of lines to generate')
    parser.add_argument('--type', choices=['json', 'text', 'mixed'], default='mixed', help='Log format type')
    
    args = parser.parse_args()
    
    # Validate script and rules exist
    if not args.generate_only:
        if not os.path.exists(args.script):
            print(f"Error: Script not found: {args.script}")
            return 1
        if not os.path.exists(args.rules):
            print(f"Error: Rules file not found: {args.rules}")
            return 1
    
    generator = TestDataGenerator()
    
    # Generate test data only
    if args.generate_only:
        output_file = args.output or f'test_data_{args.lines}_{args.type}.log'
        print(f"Generating {args.lines} lines of {args.type} logs to {output_file}")
        generator.generate_test_file(output_file, args.lines, args.type)
        print(f"Test data generated: {output_file}")
        return 0
    
    # Run performance tests
    tester = PerformanceTester(args.script, args.rules)
    results = tester.run_performance_tests()
    tester.generate_performance_report(results)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())