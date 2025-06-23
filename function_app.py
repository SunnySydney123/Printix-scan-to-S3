import azure.functions as func
import logging
import requests
import base64
import hmac
import hashlib
import json
import time
import uuid
from urllib.parse import urlparse
import os
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

app = func.FunctionApp()

def get_simple_filename(url: str, username: str = None) -> str:
    """Create a simple filename with username-date-time format"""
    try:
        # Get current timestamp for the filename
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d-%H%M%S")
        
        # Create filename with username if available
        if username:
            # Sanitize username for filename (remove special chars)
            clean_username = ''.join(c for c in username if c.isalnum() or c in [' ', '_', '-'])
            clean_username = clean_username.replace(' ', '-')
            simple_filename = f"{clean_username}-{timestamp}.pdf"
        else:
            simple_filename = f"{timestamp}.pdf"
        
        return simple_filename
    except Exception as e:
        logging.error(f"Error creating filename: {str(e)}")
        # Return a default filename if something goes wrong
        return f"document-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"

def generate_printix_signature(secret_key, request_id, timestamp, method, request_path, request_body):
    """
    Generate HMAC-SHA-256 signature for Printix
    """
    try:
        # Create string to sign according to Printix documentation
        string_to_sign = f"{request_id}.{timestamp}.{method}.{request_path}.{request_body}"
        logging.info(f"String to sign: {string_to_sign}")
        
        # Decode the secret key from base64
        secret_key_bytes = base64.b64decode(secret_key)
        
        # Create the HMAC-SHA-256 signature
        signature = hmac.new(
            secret_key_bytes, 
            string_to_sign.encode('utf-8'), 
            hashlib.sha256
        ).digest()
        
        # Encode the signature as base64
        encoded_signature = base64.b64encode(signature).decode('utf-8')
        return encoded_signature
    except Exception as e:
        logging.error(f"Error generating Printix signature: {str(e)}")
        raise

def get_printix_metadata(metadata_url, metadata_fields=None):
    """
    Query metadata from Printix with proper authentication
    """
    if not metadata_fields:
        metadata_fields = ["userName", "userEmail", "deviceId", "workflowName"]
    
    logging.info(f"Querying Printix metadata from: {metadata_url}")
    
    # Build the complete URL with query parameters
    query_string = ",".join(metadata_fields)
    full_url = f"{metadata_url}{query_string}&format=object"
    logging.info(f"Full metadata URL: {full_url}")
    
    # Get the secret key from environment variables
    secret_key = os.environ.get('PRINTIX_SECRET_KEY')
    if not secret_key:
        logging.error("No Printix secret key found. Cannot query metadata.")
        return None
    
    # Generate request ID and timestamp for authentication
    request_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    
    # Extract request path from URL
    parsed_url = urlparse(full_url)
    request_path = parsed_url.path
    if parsed_url.query:
        request_path += "?" + parsed_url.query
    
    # Generate signature for metadata request
    signature = generate_printix_signature(
        secret_key,
        request_id,
        timestamp,
        "get",
        request_path,
        ""  # Empty body for GET request
    )
    
    # Prepare headers
    headers = {
        "X-Printix-Request-Id": request_id,
        "X-Printix-Timestamp": timestamp,
        "X-Printix-Signature": signature
    }
    
    try:
        # Send GET request to Printix API
        response = requests.get(
            full_url,
            headers=headers
        )
        
        if response.status_code == 200:
            logging.info("Metadata query successful")
            return response.json()
        else:
            logging.error(f"Error querying metadata: HTTP {response.status_code}")
            logging.error(f"Response: {response.text}")
            return None
    except Exception as e:
        logging.error(f"Exception querying metadata: {str(e)}")
        return None

def upload_to_s3_from_url(document_url, file_name):
    """
    Stream file directly from Printix URL to AWS S3 bucket
    """
    logging.info(f"Starting direct upload from Printix to S3: {file_name}")
    
    # Get AWS credentials from environment variables
    aws_access_id = os.environ.get("AWS_ACCESS_ID")
    aws_access_secret = os.environ.get("AWS_ACCESS_SECRET")
    
    # Get S3 bucket name and region from environment variables, with defaults if not set
    s3_bucket = os.environ.get("AWS_S3_BUCKET_NAME", "printixscans")
    s3_region = os.environ.get("AWS_S3_REGION", "ap-southeast-2")
    
    logging.info(f"Using S3 bucket '{s3_bucket}' in region '{s3_region}'")
    
    # Validate AWS credentials
    if not aws_access_id or not aws_access_secret:
        error_msg = "AWS credentials not found in environment variables. Please set AWS_ACCESS_ID and AWS_ACCESS_SECRET."
        logging.error(error_msg)
        raise Exception(error_msg)
    
    try:
        # Download the file from Printix URL as a stream
        logging.info(f"Downloading from Printix URL: {document_url}")
        printix_response = requests.get(document_url, stream=True)
        printix_response.raise_for_status()
        
        # Initialize S3 client
        s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_id,
            aws_secret_access_key=aws_access_secret,
            region_name=s3_region
        )
        
        # Upload file to S3
        logging.info(f"Uploading stream to S3 bucket '{s3_bucket}', key '{file_name}'")
        s3_client.upload_fileobj(
            printix_response.raw,
            s3_bucket,
            file_name,
            ExtraArgs={'ContentType': 'application/pdf'}
        )
        
        # Construct the file URL based on the region and bucket
        file_url = f"https://{s3_bucket}.s3.{s3_region}.amazonaws.com/{file_name}"
        logging.info(f"File uploaded successfully to S3! URL: {file_url}")
        
        return {
            "success": True,
            "file_name": file_name,
            "file_url": file_url,
            "bucket": s3_bucket,
            "region": s3_region
        }
    
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading file from Printix: {str(e)}")
        return {"success": False, "error": str(e)}
    except ClientError as e:
        logging.error(f"Error uploading file to S3: {str(e)}")
        return {"success": False, "error": str(e)}
    except Exception as e:
        logging.error(f"Unexpected error during S3 upload: {str(e)}")
        return {"success": False, "error": str(e)}

def send_printix_callback(callback_url, request_id=None, timestamp=None):
    """
    Send a callback to Printix to indicate that the processing is complete
    """
    logging.info(f"Sending callback to Printix: {callback_url}")

    # Generate a new request ID if not provided
    if not request_id:
        request_id = str(uuid.uuid4())
    
    # Generate a timestamp if not provided
    if not timestamp:
        timestamp = str(int(time.time()))
    
    # Create the callback payload - empty errorMessage means success
    callback_payload = {
        "errorMessage": None
    }
    
    # Convert payload to JSON string with no spaces
    request_body = json.dumps(callback_payload, separators=(',', ':'))
    
    # Extract request path from URL
    parsed_url = urlparse(callback_url)
    request_path = parsed_url.path
    if parsed_url.query:
        request_path += "?" + parsed_url.query
    
    # Get the secret key from environment variables
    secret_key = os.environ.get('PRINTIX_SECRET_KEY')
    if not secret_key:
        logging.error("No Printix secret key found. Cannot generate signature.")
        return False
    
    try:
        # Generate signature
        signature = generate_printix_signature(
            secret_key,
            request_id,
            timestamp,
            "post",
            request_path,
            request_body
        )
        
        # Prepare headers
        headers = {
            "X-Printix-Request-Id": request_id,
            "X-Printix-Timestamp": timestamp,
            "X-Printix-Signature": signature,
            "Content-Type": "application/json"
        }
        
        # Send the callback to Printix
        response = requests.post(
            callback_url,
            headers=headers,
            data=request_body
        )
        
        if response.status_code == 200:
            logging.info("Callback to Printix successful")
            return True
        else:
            logging.error(f"Error sending callback to Printix: HTTP {response.status_code}")
            logging.error(f"Response: {response.text}")
            return False
    except Exception as e:
        logging.error(f"Exception sending callback to Printix: {str(e)}")
        return False

@app.route(route="showrequest", auth_level=func.AuthLevel.ANONYMOUS)
def show_request(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Received a Printix request.")
    
    try:
        # Get request body as JSON
        try:
            request_json = req.get_json()
        except ValueError:
            return func.HttpResponse(
                "Invalid JSON in request body",
                status_code=400
            )

        # Extract document URL, metadata URL and callback URL from the request
        document_url = request_json.get('documentUrl')
        metadata_url = request_json.get('metadataUrl')
        callback_url = request_json.get('callbackUrl')
        
        if not document_url:
            return func.HttpResponse(
                "No document URL found in request",
                status_code=400
            )

        logging.info(f"Document URL received: {document_url}")
        logging.info(f"Metadata URL received: {metadata_url}")
        logging.info(f"Callback URL received: {callback_url}")

        # Query metadata to get username if possible
        username = None
        if metadata_url:
            metadata = get_printix_metadata(metadata_url)
            if metadata and 'userName' in metadata:
                username = metadata['userName']
                logging.info(f"Username found in metadata: {username}")
            
            # Log other interesting metadata fields
            if metadata:
                for field in ['userEmail', 'deviceId', 'deviceLocation', 'workflowName']:
                    if field in metadata:
                        logging.info(f"Metadata {field}: {metadata[field]}")

        # Create a filename with username if available
        file_name = get_simple_filename(document_url, username)
        logging.info(f"Generated filename: {file_name}")

        # Process the file directly from Printix to S3
        try:
            # Stream the document directly from Printix to S3
            s3_result = upload_to_s3_from_url(document_url, file_name)
            
            s3_status = "Success" if s3_result.get("success", False) else "Failed"
            s3_file_url = s3_result.get('file_url', 'N/A') if s3_result.get("success", False) else 'N/A'
            s3_bucket = s3_result.get('bucket', 'N/A') if s3_result.get("success", False) else 'N/A'
            s3_region = s3_result.get('region', 'N/A') if s3_result.get("success", False) else 'N/A'
            
        except Exception as s3_error:
            logging.error(f"Error in S3 upload process: {str(s3_error)}")
            s3_status = f"Failed: {str(s3_error)}"
            s3_file_url = "N/A"
            s3_bucket = "N/A"
            s3_region = "N/A"

        # Send callback to Printix if a callback URL was provided
        callback_status = "Not attempted"
        if callback_url:
            callback_success = send_printix_callback(callback_url)
            callback_status = "Success" if callback_success else "Failed"
        
        # Create success response message
        message = (
            f"Document processed successfully!\n"
            f"File name: {file_name}\n"
            f"Direct upload to S3: {s3_status}\n"
            f"S3 Bucket: {s3_bucket}\n"
            f"S3 Region: {s3_region}\n"
            f"S3 File URL: {s3_file_url}\n"
            f"Printix Callback: {callback_status}\n"
        )
        
        # Add metadata info to response if available
        if metadata:
            message += "\nMetadata Retrieved:\n"
            for key, value in metadata.items():
                message += f"- {key}: {value}\n"

        # Return 200 OK to the original request
        return func.HttpResponse(
            message,
            mimetype="text/plain",
            status_code=200
        )

    except Exception as e:
        error_message = f"Error processing request: {str(e)}"
        logging.error(error_message)
        return func.HttpResponse(
            error_message,
            status_code=500
        )
