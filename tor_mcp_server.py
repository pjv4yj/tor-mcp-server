#!/usr/bin/env python3
"""
Tor MCP Server - Enhanced with JSON Configuration
A Model Context Protocol server that can access Tor/onion services with configurable settings
"""

import asyncio
import json
import logging
import aiohttp
import socket
import re
import os
from typing import Dict, Any, Optional, List, Set
from urllib.parse import urlparse
import sys
import aiohttp_socks

# MCP imports (you'll need to install: pip install mcp)
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

class ConfigManager:
    """Manages JSON configuration file loading and validation"""
    
    def __init__(self, config_path: str = "tor_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
                return config
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "tor_settings": {
                "socks_port": 9150,
                "host": "127.0.0.1",
                "timeout_seconds": 60,
                "connect_timeout_seconds": 30
            },
            "content_filtering": {
                "enabled": True,
                "blocked_keywords": [],
                "warning_keywords": ["ransomware", "malware", "leaked"],
                "blocked_domains": [],
                "blocked_url_patterns": [],
                "allowed_domains": [],
                "enable_content_redaction": True,
                "max_content_length": 100000
            },
            "server_settings": {
                "server_name": "tor-access",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
                "max_redirects": 5
            }
        }
    
    def get(self, path: str, default=None):
        """Get configuration value using dot notation (e.g., 'tor_settings.socks_port')"""
        keys = path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
    
    def reload_config(self):
        """Reload configuration from file"""
        self.config = self._load_config()
        logger.info("Configuration reloaded")

# =============================================================================
# CONTENT FILTERING WITH CONFIG
# =============================================================================

class ContentFilter:
    """Content filtering and safety guardrails with JSON configuration"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self._load_filter_settings()
        
    def _load_filter_settings(self):
        """Load filter settings from configuration"""
        # Get filtering enabled status
        self.enabled = self.config.get('content_filtering.enabled', True)
        
        # Load keywords (convert to sets for faster lookup)
        self.blocked_keywords = set(self.config.get('content_filtering.blocked_keywords', []))
        self.warning_keywords = set(self.config.get('content_filtering.warning_keywords', []))
        
        # Load domain settings
        self.blocked_domains = set(self.config.get('content_filtering.blocked_domains', []))
        self.allowed_domains = set(self.config.get('content_filtering.allowed_domains', []))
        
        # Load URL patterns
        self.blocked_url_patterns = self.config.get('content_filtering.blocked_url_patterns', [])
        
        # Other settings
        self.enable_content_redaction = self.config.get('content_filtering.enable_content_redaction', True)
        self.max_content_length = self.config.get('content_filtering.max_content_length', 10000)
        
        logger.info(f"Content filtering: {'enabled' if self.enabled else 'disabled'}")
        logger.info(f"Loaded {len(self.blocked_keywords)} blocked keywords, {len(self.warning_keywords)} warning keywords")
        logger.info(f"Blocked domains: {len(self.blocked_domains)}, Allowed domains: {len(self.allowed_domains)}")
        
    def reload_settings(self):
        """Reload filter settings from updated config"""
        self.config.reload_config()
        self._load_filter_settings()
        
    def is_domain_allowed(self, domain: str) -> tuple[bool, str]:
        """Check if domain is allowed"""
        if not self.enabled:
            return True, ""
            
        domain_lower = domain.lower()
        
        # Check whitelist first (if populated)
        if self.allowed_domains and domain_lower not in self.allowed_domains:
            return False, f"Domain not in allowed list: {domain}"
            
        # Check blocklist
        if domain_lower in self.blocked_domains:
            return False, f"Domain is blocked: {domain}"
            
        # Check URL patterns
        for pattern in self.blocked_url_patterns:
            if re.search(pattern, domain_lower):
                return False, f"Domain matches blocked pattern: {pattern}"
                
        return True, ""
    
    def analyze_content(self, content: str, url: str) -> tuple[str, List[str], bool]:
        """
        Analyze content for safety issues
        Returns: (filtered_content, warnings, should_block)
        """
        if not self.enabled:
            return content[:self.max_content_length], [], False
            
        content_lower = content.lower()
        warnings = []
        should_block = False
        
        # Check for blocking keywords using regex word boundaries
        for keyword_pattern in self.blocked_keywords:
            if re.search(keyword_pattern, content_lower, re.IGNORECASE):
                keyword_display = keyword_pattern.replace(r'\b', '').replace('\\b', '')
                return "", [f"Content blocked due to harmful keyword: {keyword_display}"], True
        
        # Check for warning keywords
        found_warnings = []
        for keyword in self.warning_keywords:
            if keyword in content_lower:
                found_warnings.append(f"Potentially sensitive content detected: {keyword}")
        
        # Additional heuristic checks
        if self._detect_ransomware_content(content):
            found_warnings.append("Content may be from a ransomware/leak site")
            
        if self._detect_marketplace_content(content):
            found_warnings.append("Content appears to be from an illegal marketplace")
        
        # Filter/redact sensitive content if needed
        filtered_content = self._filter_sensitive_content(content) if self.enable_content_redaction else content
        
        # Truncate if too long
        if len(filtered_content) > self.max_content_length:
            filtered_content = filtered_content[:self.max_content_length] + "\n... (content truncated for display)"
        
        return filtered_content, found_warnings, should_block
    
    def _detect_ransomware_content(self, content: str) -> bool:
        """Detect ransomware/leak site patterns (warning only for research)"""
        ransomware_indicators = [
            'ransom', 'leaked', 'stolen data', 'files downloaded',
            'pay bitcoin', 'decrypt', 'recovery key'
        ]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in ransomware_indicators)
    
    def _detect_marketplace_content(self, content: str) -> bool:
        """Detect illegal marketplace patterns"""  
        marketplace_indicators = [
            'bitcoin only', 'escrow', 'vendor', 'stealth shipping',
            'add to cart', 'cryptocurrency', 'digital goods'
        ]
        content_lower = content.lower()
        indicator_count = sum(1 for indicator in marketplace_indicators if indicator in content_lower)
        return indicator_count >= 2  # Multiple indicators suggest marketplace
    
    def _filter_sensitive_content(self, content: str) -> str:
        """Filter out sensitive information from content"""
        # Redact potential personal information
        filtered = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[REDACTED-CARD]', content)
        filtered = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', filtered)
        filtered = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED-EMAIL]', filtered)
        
        return filtered

# =============================================================================
# MAIN SERVER CLASS
# =============================================================================

class TorMCPServer:
    """MCP Server with Tor/onion service access capabilities and JSON configuration"""
    
    def __init__(self, config_path: str = "tor_config.json"):
        # Load configuration
        self.config_manager = ConfigManager(config_path)
        
        # Initialize server with configured name
        server_name = self.config_manager.get('server_settings.server_name', 'tor-access')
        self.server = Server(server_name)
        
        # Configure Tor proxy settings
        tor_host = self.config_manager.get('tor_settings.host', '127.0.0.1')
        tor_port = self.config_manager.get('tor_settings.socks_port', 9150)
        self.tor_proxy = f"socks5://{tor_host}:{tor_port}"
        
        # Initialize session and content filter
        self.session: Optional[aiohttp.ClientSession] = None
        self.content_filter = ContentFilter(self.config_manager)
        
        # Register tools
        self._register_tools()
        
        logger.info(f"Initialized Tor MCP Server with proxy: {self.tor_proxy}")
        logger.info(f"Content filtering: {'enabled' if self.content_filter.enabled else 'disabled'}")
        
    def _register_tools(self):
        """Register available tools with the MCP server"""
        
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="tor_connect",
                    description="Test connection to Tor network",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="tor_fetch",
                    description="Fetch content from a Tor/onion service URL",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "The onion service URL to fetch"
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Request timeout in seconds (default: 30)",
                                "default": 30
                            }
                        },
                        "required": ["url"]
                    }
                ),
                Tool(
                    name="tor_status",
                    description="Check Tor service status and connection",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="tor_configure_filters",
                    description="Configure content filtering settings",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["add_blocked_keyword", "remove_blocked_keyword", "add_warning_keyword", "remove_warning_keyword", "add_blocked_domain", "remove_blocked_domain", "list_filters", "reload_config"],
                                "description": "Filter configuration action"
                            },
                            "value": {
                                "type": "string",
                                "description": "Keyword or domain to add/remove (not needed for list_filters or reload_config)"
                            }
                        },
                        "required": ["action"]
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> list[TextContent]:
            if name == "tor_connect":
                return await self._test_tor_connection()
            elif name == "tor_fetch":
                url = arguments.get("url")
                timeout = arguments.get("timeout", 30)
                return await self._fetch_onion_content(url, timeout)
            elif name == "tor_status":
                return await self._check_tor_status()
            elif name == "tor_configure_filters":
                action = arguments.get("action")
                value = arguments.get("value")
                return await self._configure_filters(action, value)
            else:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]

    async def _create_tor_session(self) -> aiohttp.ClientSession:
        """Create an aiohttp session configured to use Tor SOCKS proxy"""
        if self.session and not self.session.closed:
            return self.session
            
        # Get Tor proxy URL from parsed components
        tor_host = self.config_manager.get('tor_settings.host', '127.0.0.1')
        tor_port = self.config_manager.get('tor_settings.socks_port', 9150)
        proxy_url = f'socks5://{tor_host}:{tor_port}'
        
        # Create SOCKS5 connector for Tor
        connector = aiohttp_socks.ProxyConnector.from_url(proxy_url)
        
        # Configure timeout from config
        total_timeout = self.config_manager.get('tor_settings.timeout_seconds', 60)
        connect_timeout = self.config_manager.get('tor_settings.connect_timeout_seconds', 30)
        timeout = aiohttp.ClientTimeout(total=total_timeout, connect=connect_timeout)
        
        # Get user agent from config
        user_agent = self.config_manager.get('server_settings.user_agent', 
                                           'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0')
        
        # Create session with Tor SOCKS proxy
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': user_agent}
        )
        
        return self.session

    async def _test_tor_connection(self) -> list[TextContent]:
        """Test basic Tor connection by checking IP"""
        try:
            session = await self._create_tor_session()
            
            # Test with httpbin's IP endpoint through Tor
            async with session.get('https://httpbin.org/ip') as response:
                if response.status == 200:
                    data = await response.json()
                    tor_ip = data.get('origin', 'Unknown')
                    
                    # Also get our real IP for comparison
                    async with aiohttp.ClientSession() as normal_session:
                        async with normal_session.get('https://httpbin.org/ip') as normal_response:
                            if normal_response.status == 200:
                                normal_data = await normal_response.json()
                                real_ip = normal_data.get('origin', 'Unknown')
                            else:
                                real_ip = 'Could not determine'
                    
                    result = f"""Tor Connection Test Results:
✅ Successfully connected through Tor!
🌐 Your real IP: {real_ip}
🧅 Tor exit IP: {tor_ip}
📡 Proxy: {self.tor_proxy}
                    
Connection is working properly."""
                    
                    return [TextContent(type="text", text=result)]
                else:
                    return [TextContent(
                        type="text", 
                        text=f"❌ Connection test failed. HTTP {response.status}"
                    )]
                    
        except Exception as e:
            return [TextContent(
                type="text", 
                text=f"❌ Tor connection failed: {str(e)}\n\nMake sure Tor is running on {self.tor_proxy}"
            )]

    async def _check_tor_status(self) -> list[TextContent]:
        """Check if Tor service is running and accessible"""
        try:
            # Get Tor settings from config
            tor_host = self.config_manager.get('tor_settings.host', '127.0.0.1')
            tor_port = self.config_manager.get('tor_settings.socks_port', 9150)
            
            # Try to connect to Tor SOCKS port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((tor_host, tor_port))
            sock.close()
            
            if result == 0:
                status = f"✅ Tor SOCKS proxy is running on {tor_host}:{tor_port}"
            else:
                status = f"❌ Tor SOCKS proxy is not accessible on {tor_host}:{tor_port}"
                
            return [TextContent(type="text", text=status)]
            
        except Exception as e:
            return [TextContent(
                type="text", 
                text=f"❌ Error checking Tor status: {str(e)}"
            )]

    async def _fetch_onion_content(self, url: str, timeout: int = 30) -> list[TextContent]:
        """Fetch content from an onion service URL with content filtering"""
        if not url:
            return [TextContent(type="text", text="❌ URL is required")]
            
        # Basic URL validation
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return [TextContent(type="text", text="❌ Invalid URL format")]
        
        # Check domain filtering
        domain = parsed.netloc
        is_allowed, block_reason = self.content_filter.is_domain_allowed(domain)
        if not is_allowed:
            return [TextContent(
                type="text", 
                text=f"🚫 Access blocked: {block_reason}\n\nThis domain has been filtered for safety reasons."
            )]
        
        # Check if it's an onion URL
        is_onion = parsed.netloc.endswith('.onion')
        url_type = "🧅 Onion service" if is_onion else "🌐 Regular website (via Tor)"
        
        try:
            session = await self._create_tor_session()
            
            logger.info(f"Fetching {url_type}: {url}")
            
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                if response.status == 200:
                    # Get content type and headers
                    content_type = response.headers.get('content-type', 'unknown')
                    content_size = response.headers.get('content-length', 'unknown')
                    
                    # Read content (limit to prevent huge responses)
                    content = await response.text()
                    original_size = len(content)
                    
                    # Apply content filtering
                    filtered_content, warnings, should_block = self.content_filter.analyze_content(content, url)
                    
                    if should_block:
                        return [TextContent(
                            type="text",
                            text=f"🚫 Content blocked for safety reasons:\n" + "\n".join([f"• {w}" for w in warnings])
                        )]
                    
                    # Build result with warnings if any
                    result_parts = [
                        f"✅ Successfully fetched {url_type}",
                        f"URL: {url}",
                        f"Status: {response.status} {response.reason}",
                        f"Content-Type: {content_type}",
                        f"Content-Length: {content_size} bytes",
                        f"Server: {response.headers.get('server', 'Unknown')}"
                    ]
                    
                    # Add warnings if any
                    if warnings:
                        result_parts.extend([
                            "",
                            "⚠️  CONTENT WARNINGS:",
                        ])
                        result_parts.extend([f"• {warning}" for warning in warnings])
                        result_parts.append("")
                    
                    result_parts.extend([
                        "",
                        "--- Filtered Content ---",
                        filtered_content
                    ])
                    
                    if len(content) != len(filtered_content):
                        result_parts.append(f"\n(Content filtered: {original_size} → {len(filtered_content)} characters)")
                    
                    return [TextContent(type="text", text="\n".join(result_parts))]
                    
                else:
                    return [TextContent(
                        type="text",
                        text=f"❌ Failed to fetch {url}\nHTTP {response.status}: {response.reason}"
                    )]
                    
        except asyncio.TimeoutError:
            return [TextContent(
                type="text",
                text=f"⏰ Request timed out after {timeout} seconds"
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"❌ Error fetching {url}: {str(e)}"
            )]

    async def _configure_filters(self, action: str, value: Optional[str] = None) -> list[TextContent]:
        """Configure content filtering settings"""
        try:
            if action == "reload_config":
                self.config_manager.reload_config()
                self.content_filter.reload_settings()
                # Update Tor proxy settings
                tor_host = self.config_manager.get('tor_settings.host', '127.0.0.1')
                tor_port = self.config_manager.get('tor_settings.socks_port', 9150)
                self.tor_proxy = f"socks5://{tor_host}:{tor_port}"
                # Close existing session to force recreation with new settings
                if self.session and not self.session.closed:
                    await self.session.close()
                    self.session = None
                return [TextContent(type="text", text="✅ Configuration reloaded from file")]
                
            if action == "list_filters":
                filter_info = [
                    "🛡️  Current Content Filter Configuration:",
                    "",
                    f"📊 Status: {'Enabled' if self.content_filter.enabled else 'Disabled'}",
                    f"🔌 Tor Proxy: {self.tor_proxy}",
                    f"📏 Max Content Length: {self.content_filter.max_content_length} chars",
                    f"🔒 Content Redaction: {'Enabled' if self.content_filter.enable_content_redaction else 'Disabled'}",
                    "",
                    f"📛 Blocked Keywords ({len(self.content_filter.blocked_keywords)}):",
                ]
                filter_info.extend([f"  • {keyword}" for keyword in sorted(self.content_filter.blocked_keywords)])
                
                filter_info.extend([
                    "",
                    f"⚠️  Warning Keywords ({len(self.content_filter.warning_keywords)}):",
                ])
                filter_info.extend([f"  • {keyword}" for keyword in sorted(self.content_filter.warning_keywords)])
                
                filter_info.extend([
                    "",
                    f"🚫 Blocked Domains ({len(self.content_filter.blocked_domains)}):",
                ])
                filter_info.extend([f"  • {domain}" for domain in sorted(self.content_filter.blocked_domains)])
                
                if self.content_filter.allowed_domains:
                    filter_info.extend([
                        "",
                        f"✅ Allowed Domains ({len(self.content_filter.allowed_domains)}):",
                    ])
                    filter_info.extend([f"  • {domain}" for domain in sorted(self.content_filter.allowed_domains)])
                else:
                    filter_info.extend([
                        "",
                        "✅ Allowed Domains: All except blocked (whitelist disabled)"
                    ])
                
                return [TextContent(type="text", text="\n".join(filter_info))]
            
            if not value:
                return [TextContent(type="text", text="❌ Value is required for this action")]
            
            value = value.lower().strip()
            
            if action == "add_blocked_keyword":
                self.content_filter.blocked_keywords.add(value)
                return [TextContent(type="text", text=f"✅ Added '{value}' to blocked keywords (session only - update config file to persist)")]
                
            elif action == "remove_blocked_keyword":
                if value in self.content_filter.blocked_keywords:
                    self.content_filter.blocked_keywords.remove(value)
                    return [TextContent(type="text", text=f"✅ Removed '{value}' from blocked keywords")]
                else:
                    return [TextContent(type="text", text=f"❌ '{value}' not found in blocked keywords")]
                    
            elif action == "add_warning_keyword":
                self.content_filter.warning_keywords.add(value)
                return [TextContent(type="text", text=f"✅ Added '{value}' to warning keywords")]
                
            elif action == "remove_warning_keyword":
                if value in self.content_filter.warning_keywords:
                    self.content_filter.warning_keywords.remove(value)
                    return [TextContent(type="text", text=f"✅ Removed '{value}' from warning keywords")]
                else:
                    return [TextContent(type="text", text=f"❌ '{value}' not found in warning keywords")]
                    
            elif action == "add_blocked_domain":
                self.content_filter.blocked_domains.add(value)
                return [TextContent(type="text", text=f"✅ Added '{value}' to blocked domains")]
                
            elif action == "remove_blocked_domain":
                if value in self.content_filter.blocked_domains:
                    self.content_filter.blocked_domains.remove(value)
                    return [TextContent(type="text", text=f"✅ Removed '{value}' from blocked domains")]
                else:
                    return [TextContent(type="text", text=f"❌ '{value}' not found in blocked domains")]
            
            else:
                return [TextContent(type="text", text=f"❌ Unknown action: {action}")]
                
        except Exception as e:
            return [TextContent(type="text", text=f"❌ Error configuring filters: {str(e)}")]

    async def cleanup(self):
        """Clean up resources"""
        if self.session and not self.session.closed:
            await self.session.close()

async def main():
    """Main entry point"""
    tor_server = TorMCPServer()
    
    try:
        # Run the MCP server
        async with stdio_server() as (read_stream, write_stream):
            await tor_server.server.run(
                read_stream,
                write_stream,
                tor_server.server.create_initialization_options()
            )
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    finally:
        await tor_server.cleanup()

if __name__ == "__main__":
    asyncio.run(main())