from flask import Flask, request, jsonify, render_template_string
from flask import Flask, request, jsonify, render_template_string
import re
import time

app = Flask(__name__)

# In-memory storage for tracking attempts
attempts = {}
BLOCK_DURATION = 120  # Block duration in seconds
ATTEMPT_LIMIT = 6

# Example payloads (Replace with your actual payloads)
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
SQL_INJECTION_PAYLOADS = ["' OR '1'='1", "' OR 1=1--"]

def is_malicious(payload):
    for pattern in XSS_PAYLOADS + SQL_INJECTION_PAYLOADS:
        if pattern in payload:
            return True
    return False

def sanitize_input(input_data):
    # Basic sanitization (Consider more advanced sanitization for real use cases)
    return re.sub(r'[<>\'"]', '', input_data)

@app.route('/')
def index():
    return "Welcome to Swaf - Your Secure Web App!"

@app.route('/submit', methods=['POST'])
def submit():
    user_ip = request.remote_addr
    current_time = time.time()

    # Check if the user is currently blocked
    if user_ip in attempts:
        last_attempt_time = attempts[user_ip]['last_attempt']
        if current_time - last_attempt_time < BLOCK_DURATION:
            return jsonify({"error": "You are temporarily blocked due to too many failed attempts."}), 403

    data = request.form.get('data', '')

    # Check if the input is malicious
    if is_malicious(data):
        if user_ip not in attempts:
            attempts[user_ip] = {'count': 1, 'last_attempt': current_time}
        else:
            attempts[user_ip]['count'] += 1
            attempts[user_ip]['last_attempt'] = current_time

        # Block user if the attempt limit is reached
        if attempts[user_ip]['count'] >= ATTEMPT_LIMIT:
            return jsonify({"error": "Too many failed attempts. You are blocked for 2 minutes."}), 403

        return jsonify({"error": "Malicious input detected."}), 400

    # Sanitize input and process request
    sanitized_data = sanitize_input(data)
    return jsonify({"success": f"Data received: {sanitized_data}"}), 200

@app.route('/form')
def form():
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Swaf Test Form</title>
        </head>
        <body>
            <h1>Swaf Test Form</h1>
            <form action="/submit" method="post">
                <textarea name="data" rows="4" cols="50" placeholder="Enter data"></textarea><br>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
    ''')

if __name__ == '__main__':
    app.run(debug=True)
