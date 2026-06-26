# SECURITY ISSUE: Running as root, using latest base image, hardcoded secrets
FROM python:latest

WORKDIR /app

# SECURITY ISSUE: Hardcoded credentials in environment
ENV SECRET_KEY=dev_secret_key_12345_change_in_production
ENV JWT_SECRET=jwt_super_secret_do_not_share
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV FLASK_ENV=development
ENV DEBUG=True

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# SECURITY ISSUE: Running as root
EXPOSE 5000

CMD ["python", "app.py"]
