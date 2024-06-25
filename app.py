# app.py
from flask import Flask, render_template, request
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import re
import requests

app = Flask(__name__)

# Load data
df = pd.read_csv('mail_data - mail_data.csv')

X = df['Message']
y = df['Category']

label_mapping = {'ham': 0, 'spam': 1}
y = y.map(label_mapping)

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(X)

model = MultinomialNB()
model.fit(X, y)

# Function to check URL using VirusTotal
def check_url(url):
    api_key = '6880ee59475a60b84c6b7fa032f05d50fd5710fd2015dac25bc3c77fc9c91378'
    params = {'apikey': api_key, 'resource': url}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        result = response.json()
        if result.get('response_code') == 1 and result.get('positives', 0) > 0:
            return True
    except Exception as e:
        print(f"Error checking URL: {e}")
    return False

# Function to analyze email
def analyze_email(email_content):
    # Predict using model
    content_features = vectorizer.transform([email_content])
    prediction = model.predict(content_features)[0]

    # Check URLs in email content
    urls = re.findall(r'(https?://\S+)', email_content)
    for url in urls:
        if check_url(url):
            return True

    return prediction

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        email_content = request.form['email_content']
        result = analyze_email(email_content)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
