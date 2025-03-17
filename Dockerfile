# Use the official Python image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Install the required dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose the port the app runs on
EXPOSE 8080

# Command to run the app with Gunicorn
CMD ["gunicorn", "-b", ":8080", "app:app"]