from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re
import whois
import datetime
import pickle
import numpy as np
from flask_cors import CORS
import os
import requests
import urllib
import json

app = Flask(__name__)
CORS(app)

# Load model and scaler
cwd = os.getcwd()
model_path = os.path.join(cwd, 'model.pkl')
scaler_path = os.path.join(cwd, 'scaler.pkl')

with open(model_path, 'rb') as file:
    model = pickle.load(file)

with open(scaler_path, 'rb') as sfile:
    scaler = pickle.load(sfile)

cache = {}

class IPQS:
    IPQS_API_KEY = os.getenv('IPQS_API_KEY')
    key = IPQS_API_KEY

    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
        url = f'https://www.ipqualityscore.com/api/json/url/{self.key}/{urllib.parse.quote_plus(url)}'
        x = requests.get(url, params=vars)
        x = x.json()
        print(x)
        return x

def check_with_google_safe_browsing(api_key, url):
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {"Content-Type": "application/json"}
    body = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {"key": api_key}
    response = requests.post(endpoint, headers=headers, params=params, json=body)
    print(response.json())
    return response.json()

def extract_features(url):
    feature = []
    len_url = len(url)
    feature.append(len_url)

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    len_hostname = len(hostname)
    feature.append(len_hostname)

    ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
    feature.append(1 if ip else 0)

    feature.append(url.count('.'))
    feature.append(url.count('?'))
    feature.append(url.count('='))
    feature.append(url.count('/'))
    feature.append(url.count('www'))

    feature.append(sum(c.isdigit() for c in url) / len_url if len_url > 0 else 0)
    feature.append(sum(c.isdigit() for c in hostname) / len_hostname if len_hostname > 0 else 0)

    feature.append(1 if hostname.count('.') > 1 else 0)
    feature.append(1 if '-' in hostname else 0)

    hostname_parts = hostname.split('.') if hostname else []
    feature.append(min((len(part) for part in hostname_parts), default=0))

    url_parts = re.split(r'[./?=&]', url)
    feature.append(max((len(part) for part in url_parts), default=0))

    path_parts = re.split(r'[./?=&]', parsed_url.path)
    feature.append(max((len(part) for part in path_parts), default=0))

    feature.append(0)  # Placeholder for SSL info

    feature.append(url.count('http'))
    feature.append(url.count('http') / len_url if len_url > 0 else 0)

    feature.append(1 if '<title></title>' in url else 0)
    feature.append(1 if hostname in url else 0)

    try:
        whois_info = whois.whois(hostname)
        created_date = whois_info.creation_date
        if isinstance(created_date, list):
            created_date = created_date[0]
        domain_age = (datetime.datetime.now() - created_date).days // 365 if created_date else 0
    except Exception:
        return jsonify({'url': url, 'prediction': 'Suspicious as we couldnot get whois results'})

    feature.append(domain_age)
    feature.append(-1)  # Placeholder for Google Index
    feature.append(-1)  # Placeholder for PageRank

    return np.array(feature).reshape(1, -1)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    ipqs = IPQS()

    try:
        # Call the IPQS malicious URL scanner API with strictness level 3
        result = ipqs.malicious_url_scanner_api(url, {'strictness': 3})
    
        # Check if the API call was successful
        if result.get('success', False):
            # Extract relevant information from the result
            phishing = result.get('phishing', False)
            malware = result.get('malware', False)
            suspicious = result.get('suspicious', False)
            risk_score = result.get('risk_score', 0)
    
            # Check if the URL is considered phishing, malware, or suspicious
            if phishing or malware or suspicious or risk_score >= 70:
                message = f"URL: {url}\n"
                message += "Prediction: Phishing (detected by IPQS)\n"
                message += f"Malware: {malware}\n"
                message += f"Phishing: {phishing}\n"
                message += f"Suspicious: {suspicious}\n"
                message += f"Risk Score: {risk_score}\n"
                message += f"Domain: {result.get('domain')}\n"
                message += f"Root Domain: {result.get('root_domain')}\n"
                message += f"IP Address: {result.get('ip_address')}\n"
                message += f"Status Code: {result.get('status_code')}\n"
                message += f"Page Size: {result.get('page_size')}\n"
                message += f"DNS Valid: {result.get('dns_valid')}\n"
                message += f"Domain Age: {result.get('domain_age', {}).get('human', 'N/A')}\n"
                message += f"Final URL: {result.get('final_url')}\n"
                message += f"Scanned URL: {result.get('scanned_url')}\n"
                return json({'url':url, 'prediction':message})
    except Exception as err:
        print(err)
    # Step 2: Check Google Safe Browsing
    google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if google_api_key:
        safe_browsing_result = check_with_google_safe_browsing(google_api_key, url)
        if safe_browsing_result.get("matches"):
            return jsonify({'url': url, 'prediction': 'Phishing based on Google Safe Browsing'})

    # Step 3: Check ML model
    if url in cache:
        return jsonify({'url': url, 'prediction': cache[url]})
    try:
        features = extract_features(url)
        features = scaler.transform(features)
        prediction = model.predict(features)
        result = "Phishing" if prediction[0] == 1 else "Legitimate"
        cache[url] = result
        return jsonify({'url': url, 'prediction': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False)
