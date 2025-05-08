from flask import Flask, request, render_template_string, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField
from wtforms.validators import DataRequired
import pickle
import re
import urllib.parse
import numpy as np
import socket
import ssl
import whois
from datetime import datetime
import tldextract
import aiohttp
import asyncio
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for CSRF
csrf = CSRFProtect(app)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per minute"])

# Configuration (replacing external config.json)
CONFIG = {
    "brand_names": [
        'paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix',
        'chase', 'bankofamerica', 'wellsfargo', 'linkedin', 'instagram', 'twitter'
    ],
    "shortening_services": [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 't.co',
        'cutt.ly', 'rebrand.ly', 'rb.gy'
    ]
}
SAFE_DOMAINS = ['google.com', 'microsoft.com']  # Simulating env variable

# Load model and scaler
try:
    model = pickle.load(open('phishing_model.pkl', 'rb'))
    scaler = pickle.load(open('scaler.pkl', 'rb'))
    # Validate model and scaler
    dummy_features = [0] * len(scaler.scale_)
    scaler.transform([dummy_features])
    model.predict(scaler.transform([dummy_features]))
    logger.info("Model and scaler loaded and validated successfully")
    logger.info(f"Scaler expects {len(scaler.scale_)} features")
except Exception as e:
    logger.error(f"Error loading model or scaler: {e}")
    model = None
    scaler = None

def extract_features_from_url(url):
    """Extract features from a URL for phishing detection."""
    features = []
    try:
        # Ensure URL has a protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path

        # Basic features
        features.append(len(url))                     # 1. URL length
        features.append(len(domain))                  # 2. Domain length
        features.append(len(path))                    # 3. Path length
        features.append(url.count('.'))               # 4. Number of dots
        features.append(url.count('-'))               # 5. Number of hyphens
        features.append(url.count('@'))               # 6. Number of '@' symbols
        features.append(url.count('//'))              # 7. Number of '//'
        features.append(url.count('https'))           # 8. 'https' count
        features.append(1 if 'https' in url else 0)   # 9. Using HTTPS (binary)

        # Domain-specific
        ext = tldextract.extract(domain)
        features.append(len(ext.subdomain))           # 10. Subdomain length
        features.append(domain.count('.'))            # 11. Dots in domain

        # Presence of IP address
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', domain)
        features.append(1 if ip_match else 0)         # 12. Is domain an IP?

        # Special characters
        special_chars = ['_', '=', '&', '%', '?', '#']
        features.append(sum(url.count(ch) for ch in special_chars))  # 13. Special chars count

        # URL entropy
        def calculate_entropy(string):
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = -sum(p * np.log2(p) for p in prob if p > 0)
            return entropy
        features.append(round(calculate_entropy(url), 2))  # 14. URL entropy

        # Numbers in domain
        features.append(1 if re.search(r'\d', ext.domain) else 0)  # 15. Numbers in domain

        # Query length
        features.append(len(parsed.query))              # 16. Query length

        # Sensitive keywords
        keywords = ['login', 'secure', 'account', 'update', 'verify']
        features.append(1 if any(kw in url.lower() for kw in keywords) else 0)  # 17. Keyword present

        # Path depth
        features.append(path.count('/'))                # 18. Path depth

        # URL shortening
        features.append(1 if any(service in domain for service in CONFIG['shortening_services']) else 0)  # 19. Shortened URL

        # SSL presence
        features.append(1 if url.startswith('https://') else 0)  # 20. HTTPS

        # Suspicious starting keywords
        starts_suspicious = ['secure', 'account', 'login', 'update']
        features.append(1 if any(domain.startswith(word) for word in starts_suspicious) else 0)  # 21. Starts suspicious

        # Long URL
        features.append(1 if len(url) > 75 else 0)      # 22. Long URL

        # Suspicious port
        suspicious_ports = [8080, 8443, 8888]
        features.append(1 if any(f":{port}" in url for port in suspicious_ports) else 0)  # 23. Suspicious port

        # Suspicious TLDs
        suspicious_tlds = ['xyz', 'top', 'info', 'club', 'online']
        features.append(1 if ext.suffix in suspicious_tlds else 0)  # 24. Suspicious TLD

        # Homoglyph detection
        homoglyphs = {'0': 'o', '1': 'l', '5': 's'}
        has_homoglyph = any(homoglyphs.get(c, c) != c for c in domain.lower())
        features.append(1 if has_homoglyph else 0)      # 25. Homoglyph presence

        # Validate feature count
        expected_features = len(scaler.scale_)
        if len(features) != expected_features:
            logger.error(f"Expected {expected_features} features, got {len(features)}")
            raise ValueError(f"Feature count mismatch: expected {expected_features}, got {len(features)}")

        logger.info(f"Extracted {len(features)} features for URL: {url}")
        return features

    except Exception as e:
        logger.error(f"Feature extraction failed for URL {url}: {e}")
        raise

def is_safe_domain(url):
    """Check if the URL belongs to a known safe domain using exact matching."""
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}".lower()
        return domain in SAFE_DOMAINS
    except Exception as e:
        logger.error(f"Error checking safe domain for URL {url}: {e}")
        return False

async def get_domain_age(domain):
    """Get domain age asynchronously."""
    try:
        domain_info = tldextract.extract(domain)
        domain_name = f"{domain_info.domain}.{domain_info.suffix}"
        domain_data = whois.whois(domain_name)
        if domain_data and domain_data.creation_date:
            creation_date = domain_data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now() - creation_date).days
            age_years = age_days / 365
            return f"{int(age_years)} years" if age_years >= 1 else "Less than 1 year"
        return "Unknown"
    except Exception as e:
        logger.error(f"Error checking domain age for {domain}: {e}")
        return "Unknown"

async def check_ssl(url):
    """Check SSL certificate asynchronously with validation."""
    if not url.startswith('https'):
        return "Missing"
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        async with aiohttp.ClientSession() as session:
            async with session.get(url, ssl=True) as response:
                cert = response.ssl_object.getpeercert()
                expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return "Valid" if expiry > datetime.datetime.now() else "Expired"
    except Exception as e:
        logger.error(f"Error checking SSL for {url}: {e}")
        return f"Invalid or Error: {str(e)}"

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

      // URL validation
      function isValidUrl(url) {
        try {
          new URL(url.startsWith('http') ? url : 'https://' + url);
          return true;
        } catch (e) {
          return false;
        }
      }

      urlInput.addEventListener('input', () => {
        const url = urlInput.value.trim();
        if (url === '') {
          validationMessage.style.display = 'none';
          scanBtn.disabled = true;
        } else if (isValidUrl(url)) {
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
        loadingIndicator.innerHTML = '<p>Analyzing... Please wait</p><div style="margin-top: 10px; height: 4px; width: 100%; background-color: #e2e8f0; border-radius: 2px; overflow: hidden;"><div id="progressBar" style="height: 100%; width: 0%; background-color: var(--primary); transition: width 0.3s;"></div></div>';

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
            alert('✅ Scan Complete!');
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
@limiter.limit("50 per day")
def home():
    """Render the home page"""
    return render_template_string(SHIELD_TEMPLATE)

@app.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt  # Note: CSRF protection requires form adjustments if needed
async def scan():
    """Process URL and return prediction with real data"""
    if request.method == 'POST':
        data = request.json
        url = data.get('url', '')
        logger.info(f"Received URL for scanning: {url}")

        if not url:
            return jsonify({
                'risk_status': 'Error',
                'risk_score': 0,
                'summary': 'No URL provided'
            })

        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()

            # Async checks for domain age and SSL
            domain_age, ssl_status = await asyncio.gather(
                get_domain_age(url),
                check_ssl(url)
            )

            # Known safe domains
            if is_safe_domain(url):
                return jsonify({
                    'risk_status': 'Safe',
                    'risk_score': 5,
                    'domain_age': domain_age,
                    'ssl_status': ssl_status,
                    'summary': "This URL belongs to a known safe domain."
                })

            # Extract features
            features = extract_features_from_url(url)
            if features is None:
                return jsonify({
                    'risk_status': 'Error',
                    'risk_score': 0,
                    'domain_age': domain_age,
                    'ssl_status': ssl_status,
                    'summary': 'Feature extraction failed.'
                })

            features_scaled = scaler.transform([features])
            prediction = model.predict(features_scaled)[0]
            probability = model.predict_proba(features_scaled)[0]
            phish_prob = probability[1] if len(probability) > 1 else probability[0]
            risk_score = int(phish_prob * 100)

            # Default risk status and summary
            if prediction == 1 and risk_score > 70:
                risk_status = "Dangerous"
                summary = "This URL is likely dangerous. High-risk indicators detected."
            elif risk_score > 30:
                risk_status = "Suspicious"
                summary = "This URL shows some suspicious characteristics."
            else:
                risk_status = "Safe"
                summary = "This URL appears safe based on analysis."

            # Additional checks
            # 1. Brand abuse
            for brand in CONFIG['brand_names']:
                if brand in domain and not domain.startswith(brand):
                    risk_status = "Dangerous"
                    risk_score = max(risk_score, 90)
                    summary = f"Suspicious use of brand name '{brand}' detected in the domain. Potential phishing attempt."
                    break

            # 2. URL shortening services
            for short_service in CONFIG['shortening_services']:
                if short_service in domain:
                    risk_status = "Dangerous"
                    risk_score = max(risk_score, 85)
                    summary = f"URL uses shortening service ({short_service}), which is often abused in phishing."
                    break

            # Return the final result
            return jsonify({
                'risk_status': risk_status,
                'risk_score': risk_score,
                'domain_age': domain_age,
                'ssl_status': ssl_status,
                'summary': summary,
                'confidence': float(phish_prob)
            })

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return jsonify({
                'risk_status': 'Error',
                'risk_score': 0,
                'domain_age': 'Unknown',
                'ssl_status': 'Unknown',
                'summary': f'Internal error during scanning: {str(e)}'
            })

if __name__ == '__main__':
    app.run(debug=False)  # Debug disabled for production