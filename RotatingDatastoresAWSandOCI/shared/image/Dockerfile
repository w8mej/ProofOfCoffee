# Use AWS Lambda Python 3.11 base image from public ECR
# This image is also OCI Functions container runtime compatible, enabling the same
# rotation worker code to run in both AWS Lambda and OCI Functions with zero code change.
FROM public.ecr.aws/lambda/python:3.11

# SECURITY & OPS NOTE (PoC):
#  - This is a public base image; in production, pin to a digest for immutability
#    and validate image provenance (e.g., AWS-signed digest).
#  - Multi-cloud portability is achieved by choosing a runtime both providers support.

# Copy dependency manifest to container
COPY requirements.txt .

# Install Python dependencies inside the container
# SECURITY & OPS NOTE:
#  - --no-cache-dir prevents caching of wheels, reducing image size and attack surface.
#  - Dependencies should be scanned with tools like pip-audit or Snyk before build.
#  - In production, freeze dependency versions to prevent supply chain drift.
RUN pip install -r requirements.txt --no-cache-dir

# Copy application code into container
COPY main.py .

# Set the Lambda function handler as the container's entrypoint
# SECURITY & OPS NOTE:
#  - For PoC simplicity, the handler is in a single file (main.py) with function lambda_handler.
#  - In production, split into modules, enforce logging & error handling, and avoid secrets in env.
CMD ["main.lambda_handler"]
