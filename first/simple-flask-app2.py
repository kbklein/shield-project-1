from flask import Flask, request, render_template_string, jsonify
import pickle
import re
import urllib.parse
import numpy as np
import socket
import ssl
import whois
from datetime import datetime
import tldextract
import requests
from urllib.request import urlopen
import base64
import time
from functools import lru_cache

# Initialize Flask app
app = Flask(__name__)

# Load the model and scaler
try:
    model = pickle.load(open('phishing_model.pkl', 'rb'))
    scaler = pickle.load(open('scaler.pkl', 'rb'))
    print("Model and scaler loaded successfully!")
    if hasattr(scaler, 'scale_'):
        print(f"Scaler expects {len(scaler.scale_)} features")
except Exception as e:
    print(f"Error loading model or scaler: {e}")
    model = None
    scaler = None

# Feature extraction function
def extract_features_from_url(url):
    """Extract features from a URL for phishing detection."""
    try:
        # Create a list of 23 features (all zeros)
        features = [0] * 23
        
        # Ensure URL has a protocol
        if not url.startswith('http'):
            url = 'http://' + url
        
        # Parse the URL
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        
        # Feature 1: URL Length
        features[0] = len(url)
        
        # Feature 2: Hostname Length
        features[1] = len(domain)
        
        # Feature 3: Path Length
        features[2] = len(path)
        
        # Feature 4: Number of dots in URL
        features[3] = url.count('.')
        
        # Feature 5: Number of hyphens in URL
        features[4] = url.count('-')
        
        # Fill the remaining features with 0 (already done when we initialized the array)
        
        return features
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# Check for known safe domains
def is_safe_domain(url):
    safe_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
                    'facebook.com', 'youtube.com', 'twitter.com', 'instagram.com',
                    'linkedin.com', 'github.com', 'bing.com', 'yahoo.com']
    
    for domain in safe_domains:
        if domain in url.lower():
            return True
    return False

# Get domain registration age in years
def get_domain_age(domain):
    try:
        # First extract the domain without subdomains
        domain_info = tldextract.extract(domain)
        domain_name = f"{domain_info.domain}.{domain_info.suffix}"
        
        # Query WHOIS information
        domain_data = whois.whois(domain_name)
        
        # Check if we have creation date information
        if domain_data and domain_data.creation_date:
            creation_date = domain_data.creation_date
            # Some domains return a list of dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # Calculate the age
            age_days = (datetime.now() - creation_date).days
            age_years = age_days / 365
            
            if age_years < 1:
                return "Less than 1 year"
            else:
                return f"{int(age_years)} years"
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error checking domain age: {e}")
        return "Unknown"

# Check SSL certificate
def check_ssl(url):
    try:
        if not url.startswith('https'):
            return "Missing"
        
        # Extract domain
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Create a context with the default settings for TLS/SSL connections
        context = ssl.create_default_context()
        
        # Attempt to establish a connection and get certificate info
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check if certificate is valid
                if cert:
                    return "Valid"
                else:
                    return "Invalid"
    except Exception as e:
        print(f"Error checking SSL: {e}")
        return "Invalid or Error"

# VirusTotal API integration
def check_url_with_virustotal(url, api_key):
    """
    Check URL reputation with VirusTotal.
    
    Args:
        url (str): The URL to check
        api_key (str): Your VirusTotal API key
    
    Returns:
        dict: Results including detection stats and reputation info
    """
    headers = {
        'x-apikey': api_key,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Step 1: Submit URL for analysis
    # We can use URL ID to look up existing analysis or submit a new one
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    
    try:
        # First try to get existing analysis
        analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(analysis_url, headers=headers)
        
        # If the URL hasn't been analyzed before, submit it
        if response.status_code == 404:
            submit_url = "https://www.virustotal.com/api/v3/urls"
            data = {'url': url}
            response = requests.post(submit_url, headers=headers, data=data)
            
            if response.status_code == 200:
                # Get the scan ID from the response
                analysis_id = response.json().get('data', {}).get('id')
                
                # Wait a bit for analysis to complete
                time.sleep(3)
                
                # Now get the results
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                response = requests.get(analysis_url, headers=headers)
            else:
                return {'error': f"Failed to submit URL: {response.status_code}"}
        
        # Process the results
        if response.status_code == 200:
            data = response.json().get('data', {})
            
            if 'attributes' in data:
                attributes = data['attributes']
                stats = attributes.get('stats', {})
                
                # Create a simplified result
                result = {
                    'url': url,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_engines': sum(stats.values()) if stats else 0,
                    'last_analysis_date': attributes.get('last_analysis_date')
                }
                
                # Calculate a simple reputation score
                total_checks = result['total_engines']
                if total_checks > 0:
                    malicious_ratio = (result['malicious'] + result['suspicious']) / total_checks
                    result['malicious_ratio'] = malicious_ratio
                    result['is_malicious'] = malicious_ratio > 0.05  # More than 5% engines flagged it
                else:
                    result['malicious_ratio'] = 0
                    result['is_malicious'] = False
                
                return result
            else:
                return {'error': 'No attributes in response data', 'raw_response': data}
        else:
            return {'error': f"Failed to get analysis: {response.status_code}"}
            
    except Exception as e:
        return {'error': str(e)}

# Cache results to avoid hitting rate limits
@lru_cache(maxsize=1000)
def cached_vt_check(url, timestamp_hour):
    """Cached version of VirusTotal check to respect rate limits."""
    api_key = '9ccbca59f833db9f465487951a5580654c69f1ca2e1c0cca4556e369ceb215c5'  # Replace with your actual API key
    return check_url_with_virustotal(url, api_key)

# SHIELD HTML template
SHIELD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHIELD - Phishing URL Detector</title>
  <style>
    :root {
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --secondary: #64748b;
      --danger: #ef4444;
      --success: #22c55e;
      --warning: #f59e0b;
      --dark: #0f172a;
      --light: #f8fafc;
      --border: #e2e8f0;
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    }
    
    body {
      background-color: #f1f5f9;
      color: var(--dark);
      transition: background-color 0.3s, color 0.3s;
    }
    
    body.dark-mode {
      background-color: #1e293b;
      color: #e2e8f0;
    }

    body.dark-mode .container {
      background-color: transparent;
    }

    body.dark-mode .card {
      background-color: #2d3748;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }

    body.dark-mode header {
      background: linear-gradient(135deg, #1e3a8a, #1e40af, #003087);
    }

    body.dark-mode .search-input {
      background-color: #334155;
      border-color: #4b5563;
      color: #e2e8f0;
    }

    body.dark-mode .result-card,
    body.dark-mode .detail-item {
      background-color: #334155;
    }

    body.dark-mode .action-btn {
      background-color: #4b5563;
    }

    body.dark-mode .action-btn:hover {
      background-color: #64748b;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    
    header {
      background: linear-gradient(135deg, #1a2a6c, #2a4858, #003366);
      color: white;
      padding: 30px 0;
      margin-bottom: 30px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      position: relative;
    }
    
    .header-content {
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
    }
    
    .logo {
      display: flex;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .logo-icon {
      position: relative;
      background-color: #3b82f6;
      color: white;
      border-radius: 50%;
      width: 60px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: bold;
      font-size: 24px;
      box-shadow: 0 0 15px rgba(59, 130, 246, 0.6);
    }
    
    .logo-icon::after {
      content: '';
      position: absolute;
      width: 12px;
      height: 12px;
      background-color: #f97316;
      border-radius: 50%;
      right: -3px;
      top: -3px;
      box-shadow: 0 0 8px rgba(249, 115, 22, 0.7);
    }
    
    h1 {
      font-size: 3.5rem;
      margin-bottom: 15px;
      font-weight: 800;
      letter-spacing: 4px;
      text-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
    }
    
    .subtitle {
      font-size: 1.2rem;
      opacity: 0.9;
      max-width: 600px;
      letter-spacing: 0.5px;
    }
    
    .card {
      background-color: white;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
      padding: 30px;
      margin-bottom: 30px;
    }
    
    .card-header {
      margin-bottom: 20px;
      font-size: 1.5rem;
      font-weight: 600;
    }
    
    .search-form {
      display: flex;
      margin-bottom: 20px;
      gap: 0;
    }
    
    .input-wrapper {
      position: relative;
      flex: 1;
      display: flex;
      flex-direction: column;
    }

    .search-input {
      flex: 1;
      width: 100%;
      padding: 14px 20px;
      border: 1px solid var(--border);
      border-radius: 8px 0 0 8px;
      font-size: 1rem;
      outline: none;
      transition: border 0.3s;
    }
    
    .search-input:focus {
      border-color: var(--primary);
    }

    .validation-message {
      position: absolute;
      bottom: -20px;
      left: 20px;
      font-size: 0.8rem;
      color: var(--danger);
      display: none;
    }

    .validation-message.valid {
      color: var(--success);
    }

    .scan-btn {
      background-color: var(--primary);
      color: white;
      border: none;
      border-radius: 0 8px 8px 0;
      padding: 0 25px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.3s;
      white-space: nowrap;
    }
    
    .scan-btn:hover {
      background-color: var(--primary-hover);
    }

    .scan-btn:disabled {
      background-color: var(--secondary);
      cursor: not-allowed;
    }
    
    #loadingIndicator {
      display: none;
      text-align: center;
      padding: 20px;
    }

    #progressBar {
      height: 100%;
      width: 0%;
      background-color: var(--primary);
      transition: width 0.3s;
    }

    .results {
      display: none;
      margin-top: 30px;
    }
    
    .result-card {
      background-color: white;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
      padding: 25px;
      margin-bottom: 20px;
      border-left: 5px solid var(--secondary);
    }
    
    .safe {
      border-left-color: var(--success);
    }
    
    .suspicious {
      border-left-color: var(--warning);
    }
    
    .dangerous {
      border-left-color: var(--danger);
    }
    
    .result-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .url-display {
      font-weight: 600;
      font-size: 1.1rem;
      overflow: hidden;
      text-overflow: ellipsis;
      word-break: break-all;
    }
    
    .status-badge {
      padding: 8px 16px;
      border-radius: 50px;
      font-size: 0.9rem;
      font-weight: 600;
      color: white;
    }
    
    .status-badge.safe {
      background-color: var(--success);
    }
    
    .status-badge.suspicious {
      background-color: var(--warning);
    }
    
    .status-badge.dangerous {
      background-color: var(--danger);
    }
    
    .result-details {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
      gap: 20px;
    }
    
    .detail-item {
      background-color: #f8fafc;
      border-radius: 8px;
      padding: 15px;
    }
    
    .detail-label {
      font-size: 0.9rem;
      color: var(--secondary);
      margin-bottom: 5px;
    }
    
    .detail-value {
      font-weight: 600;
    }
    
    .action-btn {
      background-color: #f1f5f9;
      border: none;
      border-radius: 6px;
      padding: 8px 12px;
      font-size: 0.9rem;
      cursor: pointer;
      transition: background-color 0.3s;
    }
    
    .action-btn:hover {
      background-color: #e2e8f0;
    }

    .theme-toggle {
      position: absolute;
      top: 20px;
      right: 20px;
      background: none;
      border: none;
      cursor: pointer;
      font-size: 1.5rem;
      color: white;
      transition: transform 0.3s ease;
    }

    .theme-toggle:hover {
      transform: scale(1.1);
    }

    @media (max-width: 768px) {
      .search-form {
        flex-direction: column;
      }
      
      .search-input {
        border-radius: 8px;
        margin-bottom: 10px;
        width: 100%;
      }
      
      .scan-btn {
        border-radius: 8px;
        padding: 14px;
        width: 100%;
      }

      .validation-message {
        position: static;
        margin-top: 5px;
        margin-bottom: 10px;
      }
      
      .result-header {
        flex-direction: column;
        align-items: flex-start;
      }
      
      .status-badge {
        margin-top: 10px;
      }

      .theme-toggle {
        top: 15px;
        right: 15px;
        font-size: 1.3rem;
      }
    }

    .search-input:focus,
    .scan-btn:focus,
    .action-btn:focus,
    .theme-toggle:focus {
      outline: 2px solid var(--primary);
      outline-offset: 2px;
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <div class="header-content">
        <div class="logo">
          <div class="logo-icon">S</div>
        </div>
        <h1>SHIELD</h1>
        <p class="subtitle">AI-powered protection against phishing attempts and malicious URLs</p>
        <button class="theme-toggle" id="themeToggle" aria-label="Toggle Dark Mode">
          🌙
        </button>
      </div>
    </div>
  </header>
  
  <div class="container">
    <div class="card">
      <h2 class="card-header">URL Analysis</h2>
      <form id="urlForm" class="search-form" role="form" aria-label="URL Scan Form">
        <div class="input-wrapper">
          <input type="text" id="urlInput" class="search-input" placeholder="Enter a URL to scan (e.g., example.com)" required aria-label="URL Input">
          <span id="validationMessage" class="validation-message" aria-live="polite"></span>
        </div>
        <button type="submit" id="scanBtn" class="scan-btn">Scan</button>
      </form>
      
      <div id="loadingIndicator" style="display: none; text-align: center; padding: 20px;">
        <p>Analyzing URL... Please wait</p>
        <div style="margin-top: 10px; height: 4px; width: 100%; background-color: #e2e8f0; border-radius: 2px; overflow: hidden;">
          <div id="progressBar" style="height: 100%; width: 0%; background-color: var(--primary); transition: width 0.3s;"></div>
        </div>
      </div>
      
      <div id="results" class="results">
        <div id="resultCard" class="result-card">
          <div class="result-header">
            <div class="url-display" id="urlDisplay"></div>
            <div class="status-badge" id="statusBadge">Safe</div>
          </div>
          <div class="result-details">
            <div class="detail-item">
              <div class="detail-label">Risk Score</div>
              <div class="detail-value" id="riskScore">0/100</div>
            </div>
            <div class="detail-item">
              <div class="detail-label">Domain Age</div>
              <div class="detail-value" id="domainAge">Unknown</div>
            </div>
            <div class="detail-item">
              <div class="detail-label">SSL Certificate</div>
              <div class="detail-value" id="sslStatus">Not Checked</div>
            </div>
            <div class="detail-item">
              <div class="detail-label">AI Confidence</div>
              <div class="detail-value" id="aiConfidence">0%</div>
            </div>
            <div class="detail-item">
              <div class="detail-label">VirusTotal</div>
              <div class="detail-value" id="vtResult">Not Checked</div>
            </div>
          </div>
          <div style="margin-top: 20px;">
            <h3 style="margin-bottom: 10px;">Analysis Summary</h3>
            <p id="analysisSummary">No analysis available yet.</p>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // Elements
      const urlForm = document.getElementById('urlForm');
      const urlInput = document.getElementById('urlInput');
      const validationMessage = document.getElementById('validationMessage');
      const scanBtn = document.getElementById('scanBtn');
      const loadingIndicator = document.getElementById('loadingIndicator');
      const progressBar = document.getElementById('progressBar');
      const results = document.getElementById('results');
      const resultCard = document.getElementById('resultCard');
      const urlDisplay = document.getElementById('urlDisplay');
      const statusBadge = document.getElementById('statusBadge');
      const riskScore = document.getElementById('riskScore');
      const domainAge = document.getElementById('domainAge');
      const sslStatus = document.getElementById('sslStatus');
      const aiConfidence = document.getElementById('aiConfidence');
      const vtResult = document.getElementById('vtResult');
      const analysisSummary = document.getElementById('analysisSummary');
      const themeToggle = document.getElementById('themeToggle');

      // Load saved theme preference
      const savedTheme = localStorage.getItem('theme') || 'light';
      document.body.classList.toggle('dark-mode', savedTheme === 'dark');
      themeToggle.textContent = savedTheme === 'dark' ? '☀️' : '🌙';

      // Theme toggle functionality
      themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        const isDarkMode = document.body.classList.contains('dark-mode');
        themeToggle.textContent = isDarkMode ? '☀️' : '🌙';
        localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
      });

      // URL validation - using a simple regex for demonstration
      const urlPattern = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w-./?%&=]*)?$/i;
      urlInput.addEventListener('input', () => {
        const url = urlInput.value.trim();
        if (url === '') {
          validationMessage.style.display = 'none';
          scanBtn.disabled = true;
        } else if (urlPattern.test(url)) {
          validationMessage.textContent = 'Valid URL';
          validationMessage.classList.add('valid');
          validationMessage.classList.remove('danger');
          validationMessage.style.display = 'block';
          scanBtn.disabled = false;
        } else {
          validationMessage.textContent = 'Invalid URL format';
          validationMessage.classList.remove('valid');
          validationMessage.classList.add('danger');
          validationMessage.style.display = 'block';
          scanBtn.disabled = true;
        }
      });

      // Form submission handler
      urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (url) {
          analyzeUrl(url);
        }
      });

      function analyzeUrl(url) {
        results.style.display = 'none';
        loadingIndicator.style.display = 'block';
        progressBar.style.width = '0%';
        
        let displayUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
          displayUrl = 'https://' + url;
        }
        
        // Progress animation
        let progress = 0;
        const analysisInterval = setInterval(() => {
          progress += 5;
          progressBar.style.width = progress + '%';
          
          if (progress >= 90) {
            clearInterval(analysisInterval);
          }
        }, 100);
        
        // Make API call to the backend
        fetch('/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url: displayUrl })
        })
        .then(response => response.json())
        .then(data => {
          // Complete the progress bar
          progressBar.style.width = '100%';
          
          setTimeout(() => {
            loadingIndicator.style.display = 'none';
            displayResults(displayUrl, data);
            results.style.display = 'block';
          }, 500);
        })
        .catch(error => {
          console.error('Error:', error);
          progressBar.style.width = '100%';
          setTimeout(() => {
            loadingIndicator.style.display = 'none';
            alert('Error analyzing URL: ' + error.message);
          }, 500);
        })
        .finally(() => {
          clearInterval(analysisInterval);
        });
      }

      function displayResults(url, data) {
        urlDisplay.textContent = url;
        riskScore.textContent = data.risk_score + '/100';
        
        domainAge.textContent = data.domain_age || 'Unknown';
        sslStatus.textContent = data.ssl_status || 'Unknown';
        
        if (data.confidence) {
          aiConfidence.textContent = Math.round(data.confidence * 100) + '%';
        } else {
          aiConfidence.textContent = Math.round(data.risk_score) + '%';
        }
        
        // Display VirusTotal results
        if (data.vt_data && data.vt_data.vt_total > 0) {
          vtResult.textContent = `${data.vt_data.vt_malicious}/${data.vt_data.vt_total} detections`;
        } else {
          vtResult.textContent = 'No data';
        }
        
        analysisSummary.textContent = data.summary;
        
        statusBadge.textContent = data.risk_status;
        
        let className;
        if (data.risk_status === 'Safe') {
          className = 'safe';
        } else if (data.risk_status === 'Suspicious') {
          className = 'suspicious';
        } else {
          className = 'dangerous';
        }
        
        statusBadge.className = 'status-badge ' + className;
        resultCard.className = 'result-card ' + className;
      }
    });
  </script>
</body>
</html>
"""

@app.route('/')
def home():
    """Render the home page"""
    return render_template_string(SHIELD_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan():
    """Process URL and return prediction with real data and VirusTotal results"""
    if request.method == 'POST':
        data = request.json
        url = data.get('url', '')
        
        print(f"Received URL for scanning: {url}")
        
        if not url:
            return jsonify({
                'risk_status': 'Error',
                'risk_score': 0,
                'summary': 'No URL provided'
            })
        
        # Get real domain age
        domain_age = get_domain_age(url)
        
        # Check real SSL certificate status
        ssl_status = check_ssl(url)
        
        # Check with VirusTotal
        current_hour = int(time.time() / 3600)  # Cache results for an hour
        vt_result = cached_vt_check(url, current_hour)
        vt_data = {
            'vt_malicious': vt_result.get('malicious', 0),
            'vt_suspicious': vt_result.get('suspicious', 0),
            'vt_harmless': vt_result.get('harmless', 0),
            'vt_undetected': vt_result.get('undetected', 0),
            'vt_total': vt_result.get('total_engines', 0),
        }
        
        # If VirusTotal clearly flags it as malicious
        if 'is_malicious' in vt_result and vt_result['is_malicious']:
            return jsonify({
                'risk_status': 'Dangerous',
                'risk_score': 90,
                'domain_age': domain_age,
                'ssl_status': ssl_status,
                'summary': f"This URL was flagged as malicious by {vt_result.get('malicious', 0)} security vendors on VirusTotal. It is highly likely to be a phishing site or to contain malware.",
                'confidence': vt_result.get('malicious_ratio', 0.9),
                'vt_data': vt_data
            })
# Check if it's a known safe domain first
        if is_safe_domain(url):
            return jsonify({
                'risk_status': 'Safe',
                'risk_score': 5,
                'domain_age': domain_age,
                'ssl_status': ssl_status,
                'summary': "This URL appears to be safe. Our analysis shows no signs of phishing or malicious content. The domain has good reputation metrics and employs standard security practices.",
                'vt_data': vt_data
            })
        
        try:
            # Extract features from URL
            features = extract_features_from_url(url)
            
            if features is None:
                return jsonify({
                    'risk_status': 'Error',
                    'risk_score': 0,
                    'domain_age': domain_age,
                    'ssl_status': ssl_status,
                    'summary': 'Could not extract features from URL',
                    'vt_data': vt_data
                })
            
            # Scale features
            features_scaled = scaler.transform([features])
            
            # Make prediction
            prediction = model.predict(features_scaled)[0]
            probability = model.predict_proba(features_scaled)[0]
            
            # Get phishing probability (usually index 1)
            phish_prob = probability[1] if len(probability) > 1 else probability[0]
            
            # Adjust risk based on VirusTotal results
            vt_weight = 0.3  # How much weight to give VirusTotal vs. ML model
            if 'malicious_ratio' in vt_result:
                # Combine scores from ML and VirusTotal
                combined_score = (phish_prob * (1 - vt_weight)) + (vt_result['malicious_ratio'] * vt_weight)
                risk_score = int(combined_score * 100)
            else:
                risk_score = int(phish_prob * 100)
            
            # Determine risk level and score
            if prediction == 1 and risk_score > 70:
                risk_status = "Dangerous"
                summary = "This URL is likely dangerous. Our analysis detected multiple high-risk indicators commonly associated with phishing or malware distribution. We strongly advise against visiting this website."
            elif risk_score > 30:
                risk_status = "Suspicious"
                summary = "This URL shows some suspicious characteristics. While not definitively malicious, we detected unusual patterns that warrant caution. The domain is relatively new and some security features are missing."
            else:
                risk_status = "Safe"
                summary = "This URL appears to be safe. Our analysis shows no signs of phishing or malicious content. The domain has good reputation metrics and employs standard security practices."
            
            # Check for brand names in suspicious positions (additional check)
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            brand_names = ['paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix']
            
            for brand in brand_names:
                if brand in domain and not domain.startswith(brand):
                    risk_status = "Dangerous"
                    risk_score = 95
                    summary = f"This URL is likely dangerous. It contains the brand name '{brand}' in a suspicious position, which is a common phishing technique."
                    break
            
            # Add VirusTotal information to summary if available
            if vt_data['vt_total'] > 0:
                vt_summary = f" VirusTotal analysis shows {vt_data['vt_malicious']} security vendors flagged this URL as malicious out of {vt_data['vt_total']} total."
                summary += vt_summary
            
            return jsonify({
                'risk_status': risk_status,
                'risk_score': risk_score,
                'domain_age': domain_age,
                'ssl_status': ssl_status,
                'summary': summary,
                'confidence': float(phish_prob),
                'vt_data': vt_data
            })
            
        except Exception as e:
            print(f"Error analyzing URL: {e}")
            return jsonify({
                'risk_status': 'Error',
                'risk_score': 0,
                'domain_age': domain_age,
                'ssl_status': ssl_status,
                'summary': f'Error analyzing URL: {str(e)}',
                'vt_data': vt_data
            })

if __name__ == '__main__':
    app.run(debug=True)