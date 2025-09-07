# -------- Dockerfile --------
# Base image
FROM python:3.12-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y python3-pyqt6 python3-pyqt6.qtsvg python3-pyqt6.qtwebsockets \
                       python3-pip python3-setuptools python3-dev build-essential \
                       net-tools iputils-ping curl && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy  code
COPY pyqt_scanner.py scanner.py requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment for X11
ENV DISPLAY=:0

# Run the app
CMD ["python3", "pyqt_scanner.py"]

