import frappe
from frappe_s3_attachment.patches.seed_s3_config import seed_s3_config_from_env

@frappe.whitelist()
def seed_s3_config():
    """
    API endpoint to manually trigger S3 configuration seeding.
    """
    try:
        result = seed_s3_config_from_env()
        return result
    except Exception as e:
        frappe.log_error(f"❌ API call failed: {str(e)}", "S3 Config Seeder API")
        return {
            "status": "error",
            "message": f"API call failed: {str(e)}"
        }