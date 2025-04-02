# Step 1: Use an official Python runtime as a parent image
FROM python:3.9-slim

# Step 2: Set the working directory in the container
WORKDIR /app

# Step 3: Copy the requirements file into the container
COPY requirements.txt .

# Step 4: Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the rest of your application into the container
COPY . .

# Step 6: Expose the port the app runs on
EXPOSE 8000

RUN chmod +x /app/entry.sh

CMD ["sh", "/app/entry.sh"]

