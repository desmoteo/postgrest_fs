# postgres.Dockerfile
# This Dockerfile creates a custom PostgreSQL image based on the official Alpine version,
# but with the necessary PL/Python 3 extension and its dependencies installed.

# Use the official PostgreSQL 15 Alpine image as the base
FROM postgres:15-alpine

# Use the Alpine package manager (apk) to add the postgresql-plpython3 package.
# This package automatically installs Python 3 and ensures it's correctly
# linked with the PostgreSQL instance in the container.
# --no-cache cleans up the package cache to keep the image size small.
RUN apk add --no-cache postgresql-plpython3 py-pip py3-fs
# Install any additional Python packages needed for your PL/Python functions.
RUN pip install fs-s3fs --break-system-packages
