from flask import Flask, render_template, request
import requests
import joblib
import re
import string
import base64

app = Flask(__name__)
model = joblib.load("spam_model.pkl")  
vectorizer = joblib.load("tfidf_vectorizer.pkl")
API_KEY = "2a21fe0307b68f7e11865079ab58640d"
NUMVERIFY_API_KEY = "3b23d9e4f04762545df63f93d6cce3f9"

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/sms-check", methods=["GET", "POST"])
def sms():
    def preprocess(text):
        text = text.lower()
        text = re.sub(r'\d+', '', text)
        text = re.sub(rf"[{string.punctuation}]", "", text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    result = None
    if request.method == "POST":
        message = request.form["message"]
        cleaned = preprocess(message)
        vector = vectorizer.transform([cleaned]).toarray()
        prediction = model.predict(vector)[0]
        result = "Spam 😡" if prediction == 1 else "Not Spam 😇"
    return render_template("index.html", result=result)

def verify_email(email):
    url = f"http://apilayer.net/api/check?access_key={API_KEY}&email={email}&smtp=1&format=1"
    response = requests.get(url)
    data = response.json()

    if data.get("format_valid") and data.get("smtp_check"):
        return True, "✅ Email is valid and exists!"
    elif data.get("format_valid"):
        return False, "⚠️ Valid format but email does not exist or SMTP check failed"
    else:
        return False, "❌ Invalid email format"

@app.route("/email-check", methods=["GET", "POST"])
def email():
    result = None
    if request.method == "POST":
        email = request.form["email"]
        status, result = verify_email(email)
    return render_template("email.html", result=result)

@app.route("/phone-check", methods=["GET", "POST"])
def phone_check():
    result = None
    if request.method == "POST":
        number = request.form["phone"]
        url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={number}&format=1"
        response = requests.get(url).json()

        if response.get("valid"):
            result = {
                "number": response["international_format"],
                "country": response["country_name"],
                "location": response["location"],
                "carrier": response["carrier"],
                "line_type": response["line_type"],
                "valid": True
            }
        else:
            result = { "valid": False }
    return render_template("phone.html", result=result)

@app.route("/url-check", methods=["GET", "POST"])
def url_check():
    result = None
    if request.method == "POST":
        input_url = request.form["url"]
        api_key = "2e0dae43bccd24c2769a4154a459309c6f3192937e34873635f19e8729597f1b"

        # Encode the URL
        encoded_url = base64.urlsafe_b64encode(input_url.encode()).decode().strip("=")
        headers = {
            "x-apikey": api_key
        }

        # Step 1: Get analysis from VirusTotal
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result = {
                "harmless": stats["harmless"],
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "undetected": stats["undetected"]
            }
        else:
            result = { "error": "Invalid URL or API limit reached." }
    return render_template("url.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
