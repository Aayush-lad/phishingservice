from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re
import whois
import datetime
import pickle
import numpy as np
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
import os
cwd = os.getcwd()
cache = {}
model_path = os.path.join(cwd, 'model.pkl')
scaler_path = os.path.join(cwd, 'scaler.pkl')

with open(model_path, 'rb') as file:
    model = pickle.load(file)
with open(scaler_path, 'rb') as sfile:
    scaler = pickle.load(sfile)

def extract_features(url):
    feature = []
    len_url = len(url)
    feature.append(len_url)
    hostname = urlparse(url).hostname or ""
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
    feature.append(min(len(word) for word in hostname.split('.')) if hostname else 0)
    feature.append(max(len(word) for word in re.split(r'[./?=&]', url)) if url else 0)
    feature.append(max(len(word) for word in re.split(r'[./?=&]', urlparse(url).path)) if urlparse(url).path else 0)
    feature.append(0)
    feature.append(url.count('http'))
    feature.append(url.count('http') / len_url if len_url > 0 else 0)
    feature.append(1 if '<title></title>' in url else 0)
    feature.append(1 if hostname in url else 0)
    
    try:
        whoisinfo = whois.whois(hostname)
        created_date = whoisinfo.creation_date[0] if isinstance(whoisinfo.creation_date, list) else whoisinfo.creation_date
        domain_age = (datetime.datetime.now() - created_date).days // 365 if created_date else 0
    except:
        domain_age = 0
    
    feature.append(domain_age)
    feature.append(-1)  # Google Index placeholder
    feature.append(-1)  # PageRank placeholder
    
    return np.array(feature).reshape(1, -1)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if url in cache:
        return jsonify({'url': url, 'prediction': cache[url]})
    
    features = extract_features(url)
    features = scaler.transform(features)
    prediction = model.predict(features)
    result = "Phishing" if prediction[0] == 1 else "Legitimate"
    print(f"URL: {url}, Prediction: {result}")
    
    return jsonify({'url': url, 'prediction': result})

if __name__ == '__main__':
    app.run(debug=False)
