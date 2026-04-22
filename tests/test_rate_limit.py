import requests
import time

# The local URL for your Flask app's login route
URL = "http://127.0.0.1:5000/login"

# Dummy data to send in the login request
PAYLOAD = {"username": "test_hacker", "password": "WrongPassword123!"}

print("Starting Brute Force Rate Limit Test...")
print("Sending 12 rapid login requests...\n")

# Loop to send 12 requests instantly (Your app limits to 10 per minute)
for attempt in range(1, 13):
    try:
        # Send a POST request to the login route
        response = requests.post(URL, json=PAYLOAD)
        
        # Check the server's response code
        if response.status_code == 429:
            print(f"Attempt {attempt}: PASSED - Server blocked the attack! (429 Too Many Requests)")
        else:
            print(f"Attempt {attempt}: Server processed the login (Status {response.status_code})")
            
        # Small delay so we don't overwhelm our own computer
        time.sleep(0.1) 
        
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect. Make sure your app.py server is running!")
        break

print("\nTest Complete.")