from __future__ import unicode_literals

import os
import re
import string
import random
import datetime
import hashlib
import time

import magic
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

import frappe



class S3Operations:
    def __init__(self):
        """
        Initialize AWS S3 settings from Frappe's S3 File Attachment singleton.
        """
        self.s3_settings_doc = frappe.get_single('S3 File Attachment')

        # Validate required settings
        if not self.s3_settings_doc.bucket_name or not self.s3_settings_doc.region_name:
            frappe.throw("S3 configuration is incomplete. Please check S3 File Attachment settings.")

        self.BUCKET = self.s3_settings_doc.bucket_name
        self.folder_name = self.s3_settings_doc.folder_name

        # Set up S3 client
        client_args = {
            "region_name": self.s3_settings_doc.region_name,
            # "config": Config(signature_version='s3v4')
        }

        if self.s3_settings_doc.aws_key and self.s3_settings_doc.aws_secret:
            client_args["aws_access_key_id"] = self.s3_settings_doc.aws_key
            client_args["aws_secret_access_key"] = self.s3_settings_doc.aws_secret

        self.S3_CLIENT = boto3.client("s3", **client_args)

        frappe.logger().info(
            f"Initialized S3 client for bucket: {self.BUCKET}, "
            f"region: {self.s3_settings_doc.region_name}, "
            f"auth: {'yes' if 'aws_access_key_id' in client_args else 'no'}"
        )

    def strip_special_chars(self, file_name):
        """
        Strips file charachters which doesnt match the regex.
        """
        regex = re.compile('[^0-9a-zA-Z._-]')
        file_name = regex.sub('', file_name)
        return file_name

    def sanitize_key_component(self, value: str) -> str:
        """Sanitize folder or file components for S3 key usage."""
        return value.replace(" ", "_").replace("/", "_").strip() if value else ""

    def key_generator(self, file_name, parent_doctype, parent_name):
        """
        Generate safe S3 key for uploading a file.
        """
        # Check if a custom hook is defined
        hook_cmd = frappe.get_hooks().get("s3_key_generator")
        if hook_cmd:
            try:
                k = frappe.get_attr(hook_cmd[0])(
                    file_name=file_name,
                    parent_doctype=parent_doctype,
                    parent_name=parent_name
                )
                if k:
                    return k.strip('/')
            except Exception:
                pass  # fail silently and continue to default logic

        # Sanitize file name and other components
        file_name = self.sanitize_key_component(self.strip_special_chars(file_name))
        parent_doctype = self.sanitize_key_component(parent_doctype)
        parent_name = self.sanitize_key_component(parent_name)
        folder = self.sanitize_key_component(self.folder_name) if self.folder_name else ""

        # Generate unique key
        timestamp = time.time()  # float with milliseconds
        hash_input = f"{timestamp}".encode("utf-8")
        unique_key = hashlib.sha1(hash_input).hexdigest()[:10]

        today = datetime.datetime.now()
        year, month, day = today.strftime("%Y"), today.strftime("%m"), today.strftime("%d")

        # Construct key
        parts = [folder, year, month, day, parent_doctype, f"{unique_key}_{file_name}"]
        final_key = "/".join(part for part in parts if part)

        frappe.logger().info(f"[S3 Upload] Generated key: {final_key}")

        return final_key

    def upload_files_to_s3_with_key(
            self, file_path, file_name, is_private, parent_doctype, parent_name
    ):
        """
        Uploads a new file to S3.
        Strips the file extension to set the content_type in metadata.
        """

        # Ensure file exists
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            frappe.throw(f"File Not Found: {abs_path}")

        mime_type = magic.from_file(abs_path, mime=True)

        key = self.key_generator(file_name, parent_doctype, parent_name)

        try:
            frappe.logger().info(f"""Uploading to S3:
                - Bucket: {self.BUCKET}
                - Region: {self.s3_settings_doc.region_name}
                - File Key: {key}
                - Local File path: {abs_path}
                - Is private: {is_private}
                - Signature Version: {self.S3_CLIENT.meta.config.signature_version}
            """)

            extra_args = {
                "ContentType": mime_type,
                "ServerSideEncryption": "AES256",
            }

            self.S3_CLIENT.upload_file(
                abs_path, self.BUCKET, key, ExtraArgs=extra_args
            )

        except boto3.exceptions.S3UploadFailedError as e:
            frappe.throw(frappe._(f"""File Upload Failed. Please try again.
                Uploading to S3:
                - Bucket: {self.BUCKET}
                - Region: {self.s3_settings_doc.region_name}
                - File Key: {key}
                - Local File path: {abs_path}
                - Is private: {is_private}
                - Signature Version: {self.S3_CLIENT.meta.config.signature_version}
                - Error: {str(e)}
            """))

        return key

    def delete_from_s3(self, key):
        """Delete file from s3"""
        self.s3_settings_doc = frappe.get_doc(
            'S3 File Attachment',
            'S3 File Attachment',
        )

        if self.s3_settings_doc.delete_file_from_cloud:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=self.s3_settings_doc.aws_key,
                aws_secret_access_key=self.s3_settings_doc.aws_secret,
                region_name=self.s3_settings_doc.region_name,
                config=Config(signature_version='s3v4')
            )

            try:
                s3_client.delete_object(
                    Bucket=self.s3_settings_doc.bucket_name,
                    Key=key
                )
            except ClientError:
                frappe.throw(frappe._("Access denied: Could not delete file"))

    def read_file_from_s3(self, key):
        """
        Function to read file from a s3 file.
        """
        return self.S3_CLIENT.get_object(Bucket=self.BUCKET, Key=key)

    def get_url(self, key, file_name=None):
        """
        Return url.

        :param bucket: s3 bucket name
        :param key: s3 object key
        """
        if self.s3_settings_doc.signed_url_expiry_time:
            self.signed_url_expiry_time = self.s3_settings_doc.signed_url_expiry_time # noqa
        else:
            self.signed_url_expiry_time = 120
        params = {
                'Bucket': self.BUCKET,
                'Key': key,

        }
        if file_name:
            params['ResponseContentDisposition'] = 'filename={}'.format(file_name)

        url = self.S3_CLIENT.generate_presigned_url(
            'get_object',
            Params=params,
            ExpiresIn=self.signed_url_expiry_time,
        )

        return url

    def public_url(self, key: str) -> str:
        return f"{self.S3_CLIENT.meta.endpoint_url}/{self.BUCKET}/{key}"

s3_upload = S3Operations()

@frappe.whitelist()
def file_upload_to_s3(doc, method):
    """
    check and upload files to s3. skips upload if doc.file_url already
    points at an existing S3 object.
    """
    s3_upload = S3Operations()
    bucket_url = s3_upload.S3_CLIENT.meta.endpoint_url.rstrip('/')
    bucket_name = s3_upload.BUCKET

    # If file_url already lives on S3, check its existence and skip
    if doc.file_url and doc.file_url.startswith(bucket_url):
        # extract key from URL: https://…/<bucket_name>/<key>
        prefix = f"{bucket_url}/{bucket_name}/"
        if doc.file_url.startswith(prefix):
            key = doc.file_url[len(prefix):]
            try:
                # head_object will throw if the key is missing
                s3_upload.S3_CLIENT.head_object(Bucket=bucket_name, Key=key)
                # already uploaded, nothing to do
                return
            except Exception:
                # object missing or access issue → fall through to re-upload
                pass

    # only non-ignored doctypes get uploaded
    parent_doctype = doc.attached_to_doctype or 'File'
    ignore = frappe.local.conf.get('ignore_s3_upload_for_doctype') or ['Data Import']
    if parent_doctype in ignore:
        return

    # determine local path
    site_path = frappe.utils.get_site_path()
    if not doc.is_private:
        file_path = site_path + '/public' + doc.file_url
    else:
        file_path = site_path + doc.file_url

    # perform upload
    key = s3_upload.upload_files_to_s3_with_key(
        file_path, doc.file_name,
        doc.is_private, parent_doctype,
        doc.attached_to_name
    )

    # build the new URL
    if doc.is_private:
        method = "frappe_s3_attachment.controller.generate_file"
        file_url = f"/api/method/{method}?key={key}&file_name={doc.file_name}"
    else:
        file_url = f"{bucket_url}/{bucket_name}/{key}"

    # clean up local and update File record
    try:
        os.remove(file_path)
    except OSError:
        pass

    frappe.db.sql("""
        UPDATE `tabFile`
        SET file_url=%s,
            folder='Home/Attachments',
            old_parent='Home/Attachments',
            content_hash=%s
        WHERE name=%s
    """, (file_url, key, doc.name))

    doc.file_url = file_url

    # if this File is an image field on its parent, sync it
    img_field = frappe.get_meta(parent_doctype).get('image_field')
    if parent_doctype and img_field:
        frappe.db.set_value(parent_doctype, doc.attached_to_name, img_field, file_url)

    frappe.db.commit()


@frappe.whitelist()
def generate_file(key=None, file_name=None):
    """
    Function to stream file from s3.
    """
    if key:
        s3_upload = S3Operations()
        signed_url = s3_upload.get_url(key, file_name)
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = signed_url
    else:
        frappe.local.response['body'] = "Key not found."
    return

def upload_existing_files_s3(name, file_name):
    """
    Function to upload all existing files.
    """
    file_doc_name = frappe.db.get_value('File', {'name': name})
    if file_doc_name:
        doc = frappe.get_doc('File', name)
        s3_upload = S3Operations()
        path = doc.file_url
        site_path = frappe.utils.get_site_path()
        parent_doctype = doc.attached_to_doctype
        parent_name = doc.attached_to_name
        if not doc.is_private:
            file_path = site_path + '/public' + path
        else:
            file_path = site_path + path
        key = s3_upload.upload_files_to_s3_with_key(
            file_path, doc.file_name,
            doc.is_private, parent_doctype,
            parent_name
        )

        if doc.is_private:
            method = "frappe_s3_attachment.controller.generate_file"
            file_url = """/api/method/{0}?key={1}""".format(method, key)
        else:
            file_url = '{}/{}/{}'.format(
                s3_upload.S3_CLIENT.meta.endpoint_url,
                s3_upload.BUCKET,
                key
            )
        os.remove(file_path)
        doc = frappe.db.sql("""UPDATE `tabFile` SET file_url=%s, folder=%s,
            old_parent=%s, content_hash=%s WHERE name=%s""", (
            file_url, 'Home/Attachments', 'Home/Attachments', key, doc.name))
        frappe.db.commit()
    else:
        pass

def s3_file_regex_match(file_url):
    """
    Match the public file regex match.
    """
    return re.match(
        r'^(https:|/api/method/frappe_s3_attachment.controller.generate_file)',
        file_url
    )

@frappe.whitelist()
def migrate_existing_files():
    """
    Function to migrate the existing files to s3.
    """
    # get_all_files_from_public_folder_and_upload_to_s3
    files_list = frappe.get_all(
        'File',
        fields=['name', 'file_url', 'file_name']
    )
    for file in files_list:
        if file['file_url']:
            if not s3_file_regex_match(file['file_url']):
                upload_existing_files_s3(file['name'], file['file_name'])
    return True

def delete_from_cloud(doc, method):
    """Delete file from s3"""
    s3 = S3Operations()
    s3.delete_from_s3(doc.content_hash)

@frappe.whitelist()
def ping():
    """
    Test function to check if api function work.
    """
    return "pong"
