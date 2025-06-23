# Printix Scan to AWS S3 — Azure Function (Python)

This Azure Function uploads a Printix scan document to an AWS S3 Bucket.  
It’s written in **Python** and developed using **VSCode**.

## 📖 Function Overview

- On a new scan, receives **webhooks from Printix**.
- Validates the incoming request using **HMAC signatures** based on the shared secret key. (PRINTIX_SECRET_KEY)
- Authenticates and retrieves metadata from Printix
- Downloads the document via a provided Printix URL
- Creates a filename using the **username from metadata** and the **current date-time**
- Uploads the document directly to an **AWS S3 bucket** (credentials and config via environment variables)
- Sends a callback to Printix confirming successful upload

## 🌐 Azure Environment Variables

Ensure the following variables are configured in your Azure Function App settings:

| Variable Name       | Description                                |
|:-------------------|:-------------------------------------------|
| `PRINTIX_SECRET_KEY`| Shared secret key for validating HMAC |
| `AWS_ACCESS_ID`     | AWS Access Key ID                          |
| `AWS_ACCESS_SECRET` | AWS Secret Access Key                      |
| `AWS_S3_BUCKET_NAME`| Target S3 bucket name                      |
| `AWS_S3_REGION`     | Your S3 region code (e.g., `ap-southeast-2`) |

---

## 🛠️ Tech Stack

- Python
- Azure Functions (Consumption Plan or App Service Plan)
- AWS S3 (via `boto3`)
- VSCode

## 📦 Installation & Deployment

To run locally:

1. Create a virtual environment:
    ```
    python -m venv .venv
    ```

2. Activate the virtual environment:
    - **Windows CMD**
        ```
        .venv\Scripts\activate
        ```

3. Install dependencies:
    ```
    pip install -r requirements.txt
    ```

4. Run locally:
    ```
    func start
    ```

5. To deploy to Azure:

