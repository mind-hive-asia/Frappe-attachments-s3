import os
import frappe
from frappe.utils import now_datetime
from mindhive_erpnext_apis.mindhive_erpnext_apis.core.services.logger import app_logger as logger
# Try to import dotenv, but handle gracefully if not available
try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    def load_dotenv(path):
        """Fallback function if python-dotenv is not available"""
        pass

def load_env_config():
    """
    Load S3 configuration from .env file.
    Returns a dict with S3 configuration values.
    """
    # Load .env file from the frappe-bench root directory
    # base directory is the directory of the current file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    logger.info(f"Base directory: {base_dir}")
    # Navigate up to frappe-bench-farmshop root: patches -> frappe_s3_attachment -> apps -> frappe-bench -> frappe-bench-farmshop
    env_path = os.path.join(base_dir, "..", "..", "..", "..", "..", ".env")
    logger.info(f"Environment path: {env_path}")
    if not os.path.exists(env_path):
        frappe.log_error(f"❌ .env file not found: {env_path}", "S3 Config Seeder")
        return {}
    
    # Load environment variables
    if DOTENV_AVAILABLE:
        load_dotenv(env_path)
    else:
        frappe.logger().warning("⚠️ python-dotenv not available, using system environment variables")
    
    # Extract S3 configuration
    s3_config = {
        "s3_file_storage": os.getenv("S3_FILE_STORAGE", "0"),
        "s3_access_key_id": os.getenv("S3_ACCESS_KEY_ID", ""),
        "s3_secret_access_key": os.getenv("S3_SECRET_ACCESS_KEY", ""),
        "s3_region": os.getenv("S3_REGION", ""),
        "s3_bucket_name": os.getenv("S3_BUCKET_NAME", ""),
        "s3_endpoint": os.getenv("S3_ENDPOINT", "")
    }
    
    # Validate required fields
    required_fields = ["s3_access_key_id", "s3_secret_access_key", "s3_region", "s3_bucket_name"]
    missing_fields = [field for field in required_fields if not s3_config.get(field)]
    
    if missing_fields:
        frappe.log_error(f"❌ Missing required S3 configuration fields: {missing_fields}", "S3 Config Seeder")
        return {}
    
    return s3_config

def get_singles_value(doctype, field, default=None):
    """
    Get a value from the singles table for a specific doctype and field.
    """
    try:
        result = frappe.db.get_single_value(doctype, field)
        return result if result is not None else default
    except:
        return default

def set_singles_value(doctype, field, value):
    """
    Set a value in the singles table for a specific doctype and field.
    """
    try:
        frappe.db.set_single_value(doctype, field, value)
        return True
    except Exception as e:
        frappe.log_error(f"Failed to set {doctype}.{field}: {str(e)}", "S3 Config Seeder")
        return False

def seed_s3_config_from_env():
    """
    Seed S3 File Attachment configuration from .env file.
    Handles the tabSingles table structure where each field is stored as a separate row.
    """
    frappe.logger().info("🚀 Starting S3 configuration seeding process...")
    
    # Load configuration from .env
    s3_config = load_env_config()
    
    if not s3_config:
        return {
            "status": "error",
            "message": "Failed to load S3 configuration from .env file"
        }
    
    try:
        doctype = "S3 File Attachment"
        updated_fields = []
        
        # Define field mappings from .env to singles table
        field_mappings = {
            "aws_key": s3_config.get("s3_access_key_id"),
            "aws_secret": s3_config.get("s3_secret_access_key"),
            "region_name": s3_config.get("s3_region"),
            "bucket_name": s3_config.get("s3_bucket_name"),
            "delete_file_from_cloud": int(s3_config.get("s3_file_storage", "0")),
            "signed_url_expiry_time": 3600,  # Default value from the image
            "folder_name": ""  # Default empty folder name
        }
        
        # Check and update each field
        for field, new_value in field_mappings.items():
            current_value = get_singles_value(doctype, field)
            
            # Convert current_value to same type as new_value for comparison
            if isinstance(new_value, int):
                current_value = int(current_value) if current_value is not None else 0
            elif isinstance(new_value, str):
                current_value = str(current_value) if current_value is not None else ""
            
            # Update if value has changed
            if current_value != new_value:
                if set_singles_value(doctype, field, new_value):
                    updated_fields.append(field)
                    frappe.logger().info(f"🔄 Updated {doctype}.{field}: {current_value} → {new_value}")
                else:
                    frappe.logger().error(f"❌ Failed to update {doctype}.{field}")
        
        # Commit changes if any were made
        if updated_fields:
            frappe.db.commit()
            frappe.logger().info(f"✔ Successfully updated {len(updated_fields)} fields: {', '.join(updated_fields)}")
            return {
                "status": "success",
                "message": f"S3 File Attachment configuration updated successfully. Updated fields: {', '.join(updated_fields)}"
            }
        else:
            frappe.logger().info("✔ S3 File Attachment configuration already up to date")
            return {
                "status": "success",
                "message": "S3 File Attachment configuration already up to date"
            }
            
    except Exception as e:
        frappe.log_error(f"❌ Failed to seed S3 configuration: {str(e)}", "S3 Config Seeder")
        frappe.db.rollback()
        return {
            "status": "error",
            "message": f"Failed to seed S3 configuration: {str(e)}"
        }

def execute():
    """
    Execute the S3 configuration seeding process.
    This function is called by the patch system.
    """
    return seed_s3_config_from_env()