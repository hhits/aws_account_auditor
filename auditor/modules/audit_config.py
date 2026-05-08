import logging
import os
import yaml

logger = logging.getLogger(__name__)

def load_config(config_path="auditor/config.yaml"):
    """
    Load configuration from a YAML file.
    
    Args:
        config_path (str): Path to the config YAML file.
    
    Returns:
        dict: Configuration dictionary or empty dict if file not found or invalid.
    """
    try:
        if not os.path.exists(config_path):
            logger.error(f"Configuration file {config_path} not found.", extra={"account_id": "N/A"})
            return {}
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        if not isinstance(config, dict):
            logger.error(f"Configuration file {config_path} is invalid.", extra={"account_id": "N/A"})
            return {}
        return config
    except Exception as e:
        logger.error(f"Error loading configuration from {config_path}: {str(e)}", extra={"account_id": "N/A"})
        return {}