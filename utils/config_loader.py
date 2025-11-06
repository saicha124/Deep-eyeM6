"""
Configuration loader utility
"""

import yaml
import os
import re
from pathlib import Path
from typing import Dict, Any
from utils.logger import get_logger

try:
    from utils.secret_manager import get_decrypted_env
except ImportError:
    def get_decrypted_env(key, default=""):
        return os.getenv(key, default)

logger = get_logger(__name__)


class ConfigLoader:
    """Load and manage configuration."""
    
    @staticmethod
    def load(config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        config_file = Path(config_path)
        
        if not config_file.exists():
            logger.warning(f"Config file not found: {config_path}")
            return ConfigLoader._get_default_config()
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Expand environment variables in config
            config = ConfigLoader._expand_env_vars(config)
            
            logger.info(f"Configuration loaded from {config_path}")
            return config
        
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return ConfigLoader._get_default_config()
    
    @staticmethod
    def _expand_env_vars(config: Any) -> Any:
        """
        Recursively expand environment variables in config.
        Supports ${VAR_NAME} syntax.
        """
        if isinstance(config, dict):
            return {k: ConfigLoader._expand_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [ConfigLoader._expand_env_vars(item) for item in config]
        elif isinstance(config, str):
            # Replace ${VAR_NAME} with environment variable value (decrypted if needed)
            pattern = r'\$\{([^}]+)\}'
            matches = re.findall(pattern, config)
            for var_name in matches:
                env_value = get_decrypted_env(var_name, '')
                if env_value:
                    config = config.replace(f'${{{var_name}}}', env_value)
                else:
                    logger.warning(f"Environment variable {var_name} not found")
            return config
        else:
            return config
    
    @staticmethod
    def _get_default_config() -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'ai_providers': {
                'openai': {
                    'enabled': False,
                    'model': 'gpt-4o',
                    'temperature': 0.7,
                    'max_tokens': 2000
                }
            },
            'scanner': {
                'default_threads': 5,
                'default_depth': 2,
                'timeout': 10,
                'user_agent': 'Deep-Eye/1.0'
            },
            'vulnerability_scanner': {
                'enabled_checks': [
                    'sql_injection',
                    'xss',
                    'command_injection',
                    'ssrf',
                    'xxe',
                    'path_traversal',
                    'csrf',
                    'open_redirect',
                    'cors_misconfiguration',
                    'security_misconfiguration'
                ],
                'payload_generation': {
                    'use_ai': False
                }
            },
            'reconnaissance': {
                'enabled_modules': []
            },
            'reporting': {
                'default_format': 'html'
            },
            'logging': {
                'level': 'INFO'
            }
        }
