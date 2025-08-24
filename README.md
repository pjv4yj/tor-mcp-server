# Tor MCP Server

A Model Context Protocol (MCP) server that provides secure access to Tor/onion services with built-in content filtering and safety guardrails. This server allows AI assistants like Claude to safely browse .onion sites and access content through the Tor network while maintaining strong safety protections.

## 🌟 Features

- **Tor Network Access**: Connect to .onion services and browse through Tor anonymously
- **Content Filtering**: Configurable keyword and domain filtering with safety guardrails
- **Safety First**: Built-in protections against harmful content with customizable filters
- **JSON Configuration**: Easy-to-manage configuration file for all settings
- **Connection Testing**: Built-in tools to verify Tor connectivity and service status
- **Content Redaction**: Automatic filtering of sensitive information (emails, SSNs, etc.)
- **Flexible Timeouts**: Configurable connection and request timeouts
- **Real-time Filter Management**: Dynamic filter configuration without restart

## 🛠️ Installation

### Prerequisites

1. **Tor Browser or Tor Service** must be running on your system
   - Download from: https://www.torproject.org/download/
   - Default SOCKS proxy runs on `127.0.0.1:9150` (Tor Browser) or `127.0.0.1:9050` (Tor service)

2. **Python 3.8+** is required

### Setup

1. Clone this repository:
```bash
git clone <your-repo-url>
cd tor-mcp-server
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create your configuration file (see Configuration section below)

4. Run the server:
```bash
python tor_mcp_server.py
```

## ⚙️ Configuration

Create a `tor_config.json` file in the same directory as the server script. Here's the default configuration:

```json
{
  "tor_settings": {
    "socks_port": 9150,
    "host": "127.0.0.1", 
    "timeout_seconds": 60,
    "connect_timeout_seconds": 30
  },
  "content_filtering": {
    "enabled": true,
    "blocked_keywords": [
      "\\bchild abuse\\b",
      "\\bdrug dealer\\b", 
      "\\bhuman trafficking\\b"
    ],
    "warning_keywords": [
      "ransomware",
      "malware", 
      "stolen data"
    ],
    "blocked_domains": [],
    "blocked_url_patterns": [
      ".*porn.*",
      ".*adult.*"
    ],
    "allowed_domains": [],
    "enable_content_redaction": true,
    "max_content_length": 100000
  },
  "server_settings": {
    "server_name": "tor-access",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
    "max_redirects": 5
  }
}
```

### Configuration Options

#### Tor Settings
- `socks_port`: Port for Tor SOCKS proxy (9150 for Tor Browser, 9050 for Tor service)
- `host`: Host address for Tor proxy (usually 127.0.0.1)
- `timeout_seconds`: Total request timeout
- `connect_timeout_seconds`: Connection establishment timeout

#### Content Filtering
- `enabled`: Enable/disable content filtering
- `blocked_keywords`: Keywords that will block content entirely (supports regex)
- `warning_keywords`: Keywords that will show warnings but allow content
- `blocked_domains`: Domain names to block completely
- `blocked_url_patterns`: URL patterns to block (regex supported)
- `allowed_domains`: Whitelist of allowed domains (empty = allow all except blocked)
- `enable_content_redaction`: Automatically redact sensitive info (emails, SSNs, etc.)
- `max_content_length`: Maximum content length to display

## 🔧 Available Tools

The server provides four main tools:

### 1. `tor_connect`
Test your Tor connection and verify it's working properly.

**Usage:**
```json
{
  "tool": "tor_connect",
  "arguments": {}
}
```

**Returns:** Connection status, your real IP vs Tor exit IP

### 2. `tor_fetch`
Fetch content from onion services or regular websites through Tor.

**Usage:**
```json
{
  "tool": "tor_fetch", 
  "arguments": {
    "url": "http://example.onion",
    "timeout": 30
  }
}
```

**Parameters:**
- `url` (required): The onion service URL or regular URL to fetch
- `timeout` (optional): Request timeout in seconds (default: 30)

### 3. `tor_status`
Check if Tor service is running and accessible.

**Usage:**
```json
{
  "tool": "tor_status",
  "arguments": {}
}
```

### 4. `tor_configure_filters`
Dynamically configure content filtering settings.

**Usage:**
```json
{
  "tool": "tor_configure_filters",
  "arguments": {
    "action": "add_blocked_keyword",
    "value": "malicious_term"
  }
}
```

**Actions:**
- `add_blocked_keyword` / `remove_blocked_keyword`
- `add_warning_keyword` / `remove_warning_keyword` 
- `add_blocked_domain` / `remove_blocked_domain`
- `list_filters`: Show current filter configuration
- `reload_config`: Reload configuration from file

## 🛡️ Safety Features

### Content Filtering
- **Keyword Filtering**: Block or warn on configurable keywords (with regex support)
- **Domain Blocking**: Block entire domains or URL patterns
- **Content Analysis**: Heuristic detection of ransomware sites and illegal marketplaces
- **Content Redaction**: Automatic removal of emails, SSNs, credit cards from displayed content

### Built-in Protections
- Blocks harmful content categories by default
- Warns on potentially dangerous content
- Rate limiting and content size limits
- Safe defaults with ability to customize

### Responsible Use
This tool is designed for:
- ✅ Security research and education
- ✅ Privacy-focused browsing
- ✅ Accessing legitimate onion services
- ✅ Investigating threats for cybersecurity purposes

**Not intended for:**
- ❌ Accessing illegal content
- ❌ Bypassing legitimate restrictions
- ❌ Any harmful or illegal activities

## 🚀 Usage with Claude/MCP

1. Start the Tor MCP Server
2. Configure your MCP client to connect to the server
3. Use natural language commands:
   - "Test my Tor connection"
   - "Fetch content from [onion-url]"
   - "Check if Tor is running"
   - "Add 'suspicious-term' to blocked keywords"

## 📋 Requirements

- Python 3.8+
- Tor Browser or Tor service running
- Dependencies from `requirements.txt`:
  - mcp>=1.0.0
  - aiohttp>=3.8.0
  - aiohttp-socks>=0.8.0
  - pydantic>=2.0.0
  - openai>=1.0.0

## 🔍 Troubleshooting

### Common Issues

**"Tor connection failed"**
- Ensure Tor Browser is running or Tor service is started
- Check if the SOCKS port (9150/9050) is correct
- Verify host/port settings in config

**"Content blocked"**
- Content triggered safety filters
- Review and adjust `blocked_keywords` or `blocked_domains` in config
- Use `tor_configure_filters` to modify filters

**"Request timed out"**
- Increase timeout values in config
- Onion services can be slow - try longer timeouts
- Check if the onion service is online

### Debug Mode
Run with verbose logging:
```bash
PYTHONPATH=. python tor_mcp_server.py --verbose
```

## 📝 License

This project is provided for educational and research purposes. Users are responsible for ensuring their usage complies with local laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## ⚠️ Disclaimer

This tool is for legitimate security research and privacy purposes only. The authors are not responsible for misuse. Always comply with applicable laws and use responsibly.

---

**Need help?** Open an issue on GitHub or check the troubleshooting section above.
