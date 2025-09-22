# Security Log Redaction Tool

A fast, configurable, and production-ready tool for masking sensitive information in security logs. Supports streaming processing, flexible rule configuration, and integration with popular log processing pipelines.

## 🚀 Features

- **High Performance**: Processes 50-100MB/s on typical hardware
- **Flexible Configuration**: YAML-based rules for different data types and patterns
- **Multiple Redaction Strategies**: Mask, hash, remove, or tokenize sensitive data
- **JSON & Text Support**: Handles structured JSON logs and plain text formats
- **Pipeline Integration**: Works with Fluent Bit, Vector, Logstash, and more
- **Streaming Processing**: Memory-efficient line-by-line processing
- **Statistics & Monitoring**: Built-in performance metrics and monitoring

## 🎯 Protected Information Types

### Identity & Authentication
- Usernames, emails, phone numbers
- ID cards, social security numbers
- API keys, tokens, JWT
- Passwords, secrets, certificates

### Network & Infrastructure  
- IP addresses (IPv4/IPv6), MAC addresses
- Internal hostnames, domain names
- Device identifiers (IMEI, ICCID, UUID)

### Financial & Personal
- Bank cards, credit cards
- Geographic coordinates
- Personal identifiable information (PII)

## 📦 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd security_source

# Install dependencies
pip install -r requirements.txt

# Generate encryption salt
export REDACT_SALT="$(openssl rand -hex 32)"
```

### Basic Usage

```bash
# Process logs from stdin
cat security.log | python3 redact.py --rules redaction-rules.yaml > clean.log

# Process file directly with statistics
python3 redact.py --rules redaction-rules.yaml --input security.log --output clean.log --stats

# Validate configuration
python3 redact.py --rules redaction-rules.yaml --validate-config
```

### Example Output

**Before:**
```json
{"user": "john.doe", "email": "john@company.com", "phone": "13812345678", "ip": "192.168.1.100", "token": "abc123secret"}
```

**After:**
```json
{"user": "john.doe", "email": "j***@company.com", "phone": "138****5678", "ip": "192.168.1.xxx/*h=v1:a1b2c3d4*/", "token": "***/*h=v1:e5f6g7h8*/"}
```

## 🔧 Configuration

The tool uses YAML configuration files to define redaction rules. See `redaction-rules.yaml` for the complete configuration.

### Key Configuration Sections

#### 1. Sensitive Key Denylist
```yaml
key_denylist:
  - password
  - token
  - api_key
  - secret
```

#### 2. Redaction Actions
```yaml
actions:
  - name: pii-mask
    type: regex
    action: mask
    rules:
      - field_hint: phone_cn
        pattern: '(\b1[3-9]\d)(\d{4})(\d{4}\b)'
        replacement: '$1****$3'
```

#### 3. JSON Key Rules
```yaml
- name: json-key-deny
  type: json_key
  rules:
    - keys: [password, secret]
      action: remove
    - keys: [email, phone]
      action: mask_and_hash
```

### Redaction Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `mask` | Replace with `***` or pattern | Phone numbers, emails |
| `hash` | HMAC-SHA256 with salt | Correlation without exposure |
| `remove` | Complete removal | Passwords, private keys |
| `mask_and_hash` | Mask + hash for correlation | IP addresses, user IDs |

## 🚀 Performance Testing

Run performance benchmarks to validate throughput:

```bash
# Run comprehensive performance tests
python3 test_performance.py --script redact.py --rules redaction-rules.yaml

# Generate test data only
python3 test_performance.py --generate-only --lines 100000 --type mixed --output test.log

# Test specific file
python3 test_performance.py --script redact.py --rules redaction-rules.yaml --input test.log
```

Expected performance on modern hardware:
- **50-100 MB/s** for mixed JSON/text logs
- **10,000-50,000 lines/second** depending on complexity
- **Memory usage**: <512MB for streaming processing

## 🔗 Pipeline Integration

### Fluent Bit

```conf
[FILTER]
    Name    command
    Match   app.*
    Command python3 /opt/redact.py --rules /opt/redaction-rules.yaml
```

### Vector

```toml
[transforms.redact]
  type = "exec"
  inputs = ["logs"]
  command = ["python3", "/opt/redact.py", "--rules", "/opt/redaction-rules.yaml"]
```

### Logstash

```ruby
filter {
  ruby {
    code => '
      cmd = "python3 /opt/redact.py --rules /opt/redaction-rules.yaml"
      out, _ = Open3.capture2(cmd, stdin_data: event.get("message"))
      event.set("message", out.strip)
    '
  }
}
```

See `examples/` directory for complete configuration files.

## 🐳 Docker Deployment

### Build and Run

```bash
# Build Docker image
docker build -f examples/docker/Dockerfile -t log-redactor .

# Run container
docker run -e REDACT_SALT="$(openssl rand -hex 32)" \
           -v $(pwd)/logs:/var/log:ro \
           -v $(pwd)/output:/var/log/redacted \
           log-redactor --rules redaction-rules.yaml --input /var/log/app.log
```

### Docker Compose

```bash
# Start complete log processing stack
cd examples/docker
export REDACT_SALT="$(openssl rand -hex 32)"
docker-compose up -d

# Check processing status
docker-compose logs fluent-bit
```

## 📊 Monitoring & Statistics

Enable statistics collection:

```bash
python3 redact.py --rules redaction-rules.yaml --stats < input.log > output.log
```

Example output:
```
[STATS] Processed 50000 lines, 15000 redactions, 2500.0 lines/sec
```

The tool provides:
- Lines processed per second
- Total redactions applied  
- JSON objects processed
- Processing time metrics

## 🔒 Security Considerations

### Salt Management
```bash
# Generate strong salt
export REDACT_SALT="$(openssl rand -hex 32)"

# Rotate salt periodically
export REDACT_SALT_V2="$(openssl rand -hex 32)"
```

### Production Deployment
- Use dedicated service accounts with minimal permissions
- Store configuration in secure, version-controlled locations
- Monitor processing performance and error rates
- Implement log rotation for redacted outputs
- Regular security audits of redaction effectiveness

### Validation & Testing
```bash
# Test configuration
python3 redact.py --validate-config --rules redaction-rules.yaml

# Run test suite (if available)
python3 -m pytest tests/

# Performance validation
python3 test_performance.py
```

## 📋 Common Patterns Reference

### Regular Expressions

| Pattern | Regex | Description |
|---------|-------|-------------|
| Chinese Phone | `(\b1[3-9]\d)(\d{4})(\d{4}\b)` | Mobile numbers |
| Email | `([A-Za-z0-9._%+\-])[^@]*(@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})` | Email addresses |
| IPv4 | `(?<![0-9])((?:\d{1,3}\.){3}\d{1,3})(?![0-9])` | IP addresses |
| Chinese ID | `(\b\d{6})\d{8}(\w{4}\b)` | Identity cards |
| AWS Key | `(?i)(AKIA[0-9A-Z]{16})` | AWS access keys |
| JWT | `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+` | JWT tokens |

### Field Name Patterns

Common sensitive field names automatically detected:
- `password`, `passwd`, `pwd`
- `token`, `access_token`, `refresh_token`
- `api_key`, `apikey`, `x-api-key`
- `secret`, `client_secret`
- `phone`, `mobile`, `email`
- `id_card`, `ssn`, `bankcard`

## 🛠️ Customization

### Adding New Patterns

1. Edit `redaction-rules.yaml`
2. Add pattern to appropriate action:

```yaml
- name: custom-pattern
  type: regex
  action: mask
  patterns:
    - 'your-regex-pattern-here'
```

3. Test the configuration:

```bash
python3 redact.py --validate-config --rules redaction-rules.yaml
```

### Custom Field Types

Add JSON key rules for application-specific fields:

```yaml
- name: app-specific
  type: json_key
  rules:
    - keys: [custom_user_id, internal_token]
      action: mask_and_hash
```

## 🚨 Troubleshooting

### Common Issues

**Performance Issues:**
- Increase `max_line_len` for very long log lines
- Use `chunk_size` tuning in performance section
- Consider parallel processing for large files

**Memory Usage:**
- Monitor `max_memory_mb` setting
- Use streaming processing for large files
- Check for regex backtracking in complex patterns

**Configuration Errors:**
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('redaction-rules.yaml'))"

# Test regex patterns
python3 -c "import re; re.compile('your-pattern')"
```

### Debug Mode

Enable verbose logging:

```bash
# Set log level in configuration
logging:
  level: DEBUG
  include_stats: true
```

## 📚 Additional Resources

- [Configuration Examples](examples/)
- [Performance Testing](test_performance.py)
- [Docker Deployment](examples/docker/)
- [Pipeline Integration](examples/)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-pattern`
3. Add tests for new functionality
4. Submit pull request

## 📄 License

[Add your license information here]

## 📞 Support

For issues and questions:
- Create GitHub issues for bugs and feature requests
- Check existing patterns in configuration file
- Review examples for integration guidance