import os
from flask import Flask, request, jsonify, Response
import json
import requests
import logging
import random
import time
from urllib.parse import parse_qs, urlparse, unquote
import re
from concurrent.futures import ThreadPoolExecutor
import threading

app = Flask(__name__)

# ====== 🇮🇳 ==============
# # © Developer = WOODcraft 
# ========================
# Configuration
COOKIES_FILE = 'cookies.txt'
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2
PORT = 3000

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Thread pool for operations
executor = ThreadPoolExecutor(max_workers=5)

# User agents list
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
]

def get_random_headers():
    """Generate random headers for requests"""
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'DNT': '1'
    }
    return headers

def load_cookies():
    """Load cookies from Netscape format file"""
    cookies_dict = {}
    if os.path.exists(COOKIES_FILE):
        try:
            with open(COOKIES_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        name = parts[5]
                        value = parts[6]
                        cookies_dict[name] = value
            logger.info(f"Loaded {len(cookies_dict)} cookies")
        except Exception as e:
            logger.error(f"Error loading cookies: {str(e)}")
    else:
        logger.warning(f"Cookies file {COOKIES_FILE} not found")
    
    return cookies_dict

def find_between(string, start, end):
    """Extract text between two delimiters"""
    try:
        start_index = string.find(start)
        if start_index == -1:
            return None
        start_index += len(start)
        end_index = string.find(end, start_index)
        if end_index == -1:
            return None
        return string[start_index:end_index]
    except Exception:
        return None

def make_request(url, method='GET', headers=None, params=None, cookies=None, allow_redirects=True, timeout=None):
    """Make HTTP request with retry logic using requests library"""
    session = requests.Session()
    
    # Set cookies
    if cookies:
        session.cookies.update(cookies)
    
    # Set headers
    if headers:
        session.headers.update(headers)
    else:
        session.headers.update(get_random_headers())
    
    retry_count = 0
    last_exception = None
    
    while retry_count < MAX_RETRIES:
        try:
            # Add random delay to avoid rate limiting
            if retry_count > 0:
                time.sleep(random.uniform(2, 5))
            
            response = session.request(
                method=method,
                url=url,
                params=params,
                allow_redirects=allow_redirects,
                timeout=timeout or REQUEST_TIMEOUT,
                verify=False  # Disable SSL verification
            )
            
            if response.status_code == 403:
                logger.warning(f"Blocked by server (403), retrying... (attempt {retry_count + 1})")
                retry_count += 1
                time.sleep(RETRY_DELAY * (retry_count + 2))
                continue
            elif response.status_code == 429:
                logger.warning(f"Rate limited (429), retrying... (attempt {retry_count + 1})")
                retry_count += 1
                time.sleep(RETRY_DELAY * (retry_count + 3))
                continue
            elif response.status_code >= 500:
                logger.warning(f"Server error ({response.status_code}), retrying... (attempt {retry_count + 1})")
                retry_count += 1
                time.sleep(RETRY_DELAY * (retry_count + 1))
                continue
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error: {str(e)}, retrying... (attempt {retry_count + 1})")
            retry_count += 1
            last_exception = e
            time.sleep(RETRY_DELAY * (retry_count + 2))
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timeout, retrying... (attempt {retry_count + 1})")
            retry_count += 1
            last_exception = e
            time.sleep(RETRY_DELAY * (retry_count + 1))
        except Exception as e:
            logger.warning(f"Request failed: {str(e)}, retrying... (attempt {retry_count + 1})")
            retry_count += 1
            last_exception = e
            time.sleep(RETRY_DELAY * (retry_count + 1))
        finally:
            session.close()
    
    raise Exception(f"Max retries exceeded. Last error: {str(last_exception)}")

def extract_tokens_from_html(html_content):
    """Extract tokens from HTML using multiple methods"""
    tokens = {}
    
    # Method 1: Extract jsToken
    js_token_patterns = [
        r'fn%28%22([^%]+)%22%29',
        r'"jsToken":"([^"]+)"',
        r'jsToken%22%3A%22([^%]+)%22',
        r'jsToken["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in js_token_patterns:
        match = re.search(pattern, html_content)
        if match:
            tokens['js_token'] = unquote(match.group(1))
            break
    
    # Method 2: Extract logid
    logid_patterns = [
        r'dp-logid=([^&]+)',
        r'"logid":"([^"]+)"',
        r'dplogid":"([^"]+)"',
        r'logid["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in logid_patterns:
        match = re.search(pattern, html_content)
        if match:
            tokens['log_id'] = match.group(1)
            break
    
    return tokens

def extract_surl_from_url(url):
    """Extract surl from TeraBox URL"""
    # Method 1: From query parameter
    if 'surl=' in url:
        return url.split('surl=')[1].split('&')[0]
    
    # Method 2: From path
    if '/s/' in url:
        return url.split('/s/')[1].split('?')[0].split('/')[0]
    
    # Method 3: From hash
    if '#' in url and 'surl=' in url:
        return url.split('surl=')[1].split('&')[0]
    
    return None

def fetch_download_links(url):
    """Fetch download links from TeraBox URL"""
    try:
        cookies = load_cookies()
        if not cookies:
            raise Exception("No cookies found. Please provide valid cookies in cookies.txt file.")
        
        logger.info(f"Processing URL: {url}")
        
        # Step 1: Get initial page
        headers = get_random_headers()
        headers['Referer'] = 'https://www.terabox.com/'
        
        response = make_request(url, headers=headers, cookies=cookies)
        html_content = response.text
        final_url = response.url
        
        logger.info(f"Got response from: {final_url}")
        
        # Step 2: Extract tokens
        tokens = extract_tokens_from_html(html_content)
        
        if not tokens.get('js_token'):
            logger.error("Could not extract jsToken")
            raise Exception("Could not extract required jsToken from the page")
        
        if not tokens.get('log_id'):
            logger.error("Could not extract logid")
            raise Exception("Could not extract required logid from the page")
        
        logger.info(f"Extracted tokens - jsToken: {tokens['js_token'][:10]}..., logid: {tokens['log_id']}")
        
        # Step 3: Extract surl
        surl = extract_surl_from_url(final_url) or extract_surl_from_url(url)
        
        if not surl:
            logger.error(f"Could not extract surl from URL: {final_url}")
            raise Exception("Could not extract surl from URL")
        
        logger.info(f"Extracted surl: {surl}")
        
        # Step 4: Prepare API parameters
        params = {
            'app_id': '250528',
            'web': '1',
            'channel': 'dubox',
            'clienttype': '0',
            'jsToken': tokens['js_token'],
            'dplogid': tokens['log_id'],
            'page': '1',
            'num': '20',
            'order': 'time',
            'desc': '1',
            'site_referer': final_url,
            'shorturl': surl,
            'root': '1'
        }
        
        # Step 5: Make API request
        api_endpoints = [
            'https://www.terabox.com/share/list',
            'https://terabox.com/share/list',
            'https://www.1024tera.com/share/list'
        ]
        
        list_data = None
        for endpoint in api_endpoints:
            try:
                logger.info(f"Trying API endpoint: {endpoint}")
                
                api_headers = get_random_headers()
                api_headers.update({
                    'Referer': final_url,
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json, text/plain, */*'
                })
                
                # Add delay before API call
                time.sleep(random.uniform(1, 3))
                
                response = make_request(
                    endpoint,
                    params=params,
                    headers=api_headers,
                    cookies=cookies,
                    timeout=30
                )
                
                list_data = response.json()
                
                if 'list' in list_data and list_data['list']:
                    logger.info(f"Successfully got data from {endpoint}")
                    break
                else:
                    logger.warning(f"No data in response from {endpoint}")
                    
            except Exception as e:
                logger.warning(f"Failed to get data from {endpoint}: {str(e)}")
                continue
        
        if not list_data or 'list' not in list_data or not list_data['list']:
            raise Exception("No files found in the shared link")
        
        logger.info(f"Found {len(list_data['list'])} items")
        
        # Step 6: Handle directories
        files = list_data['list']
        if files[0].get('isdir') == 1 or files[0].get('isdir') == "1":
            logger.info("First item is a directory, fetching directory contents")
            
            dir_params = params.copy()
            dir_params.update({
                'dir': files[0]['path'],
                'order': 'name',
                'desc': '0'
            })
            dir_params.pop('root', None)
            
            for endpoint in api_endpoints:
                try:
                    time.sleep(random.uniform(1, 2))
                    
                    response = make_request(
                        endpoint,
                        params=dir_params,
                        headers=api_headers,
                        cookies=cookies,
                        timeout=30
                    )
                    
                    dir_data = response.json()
                    if 'list' in dir_data and dir_data['list']:
                        logger.info(f"Successfully got directory data from {endpoint}")
                        files = dir_data['list']
                        break
                except Exception as e:
                    logger.warning(f"Failed to get directory data from {endpoint}: {str(e)}")
                    continue
            else:
                raise Exception("No files found in the directory")
        
        return files
        
    except Exception as e:
        logger.error(f"Error in fetch_download_links: {str(e)}")
        raise

def get_direct_link(dlink, cookies):
    """Get direct download link by following redirects properly"""
    try:
        if not dlink:
            return ""
        
        logger.info(f"Getting direct link for: {dlink[:50]}...")
        
        # Create session with proper headers
        session = requests.Session()
        session.cookies.update(cookies)
        
        headers = get_random_headers()
        headers.update({
            'Referer': 'https://www.terabox.com/',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        
        # Follow redirects manually to get the final URL
        current_url = dlink
        redirect_count = 0
        max_redirects = 10
        
        while redirect_count < max_redirects:
            try:
                response = session.get(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=15,
                    verify=False
                )
                
                # Check for redirect
                if 300 <= response.status_code < 400:
                    if 'Location' in response.headers:
                        current_url = response.headers['Location']
                        redirect_count += 1
                        
                        # Check if this is a direct download URL
                        if any(domain in current_url for domain in ['d.1024tera.com', 'nfile.1024tera.com', 'd2.terabox.com', 'd3.terabox.com']):
                            logger.info(f"Found direct download URL after {redirect_count} redirects")
                            session.close()
                            return current_url
                        
                        # Small delay between redirects
                        time.sleep(0.5)
                        continue
                    else:
                        break
                elif response.status_code == 200:
                    # Check if current URL is already a direct download URL
                    if any(domain in current_url for domain in ['d.1024tera.com', 'nfile.1024tera.com', 'd2.terabox.com', 'd3.terabox.com']):
                        logger.info("URL is already a direct download link")
                        session.close()
                        return current_url
                    else:
                        # Try to extract download URL from response
                        content = response.text
                        
                        # Look for download URLs in the response content
                        download_patterns = [
                            r'"(https?://[^"]*(?:d\.1024tera\.com|nfile\.1024tera\.com|d2\.terabox\.com|d3\.terabox\.com)[^"]*)"',
                            r"'(https?://[^']*(?:d\.1024tera\.com|nfile\.1024tera\.com|d2\.terabox\.com|d3\.terabox\.com)[^']*)'",
                            r'href="([^"]*(?:d\.1024tera\.com|nfile\.1024tera\.com|d2\.terabox\.com|d3\.terabox\.com)[^"]*)"'
                        ]
                        
                        for pattern in download_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                direct_url = matches[0]
                                logger.info("Found direct download URL in response content")
                                session.close()
                                return direct_url
                        
                        break
                else:
                    logger.warning(f"Unexpected status code: {response.status_code}")
                    break
                    
            except requests.exceptions.Timeout:
                logger.warning("Timeout while getting direct link")
                break
            except Exception as e:
                logger.warning(f"Error during redirect: {str(e)}")
                break
        
        session.close()
        
        # If we couldn't get a direct link, return the original dlink
        logger.warning("Could not resolve to direct download URL, returning original dlink")
        return dlink
        
    except Exception as e:
        logger.warning(f"Could not get direct link for {dlink}: {str(e)}")
        return dlink

def format_size(size_bytes):
    """Format file size in human readable format"""
    try:
        size_bytes = int(size_bytes)
        if size_bytes >= 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
        elif size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        elif size_bytes >= 1024:
            return f"{size_bytes / 1024:.2f} KB"
        return f"{size_bytes} bytes"
    except Exception:
        return "Unknown size"

def process_files(files, cookies):
    """Process file list and get download links"""
    results = []
    
    for i, file_data in enumerate(files[:5]):  # Limit to 5 files
        try:
            logger.info(f"Processing file {i+1}/{min(len(files), 5)}: {file_data.get('server_filename', 'Unknown')}")
            
            # Get direct link
            dlink = file_data.get('dlink', '')
            direct_link = get_direct_link(dlink, cookies) if dlink else ""
            
            result = {
                "file_name": file_data.get("server_filename", "Unknown"),
                "size": format_size(file_data.get("size", 0)),
                "size_bytes": int(file_data.get("size", 0)),
                "download_url": dlink,
                "direct_download_url": direct_link,
                "is_directory": file_data.get("isdir", 0) == 1 or file_data.get("isdir", "0") == "1",
                "modify_time": file_data.get("server_mtime", 0),
                "thumbnails": file_data.get("thumbs", {}) if file_data.get("thumbs") else {},
                "path": file_data.get("path", ""),
                "category": file_data.get("category", 0),
                "fs_id": file_data.get("fs_id", ""),
                "md5": file_data.get("md5", "")
            }
            
            results.append(result)
            
            # Add delay between processing
            if i < min(len(files), 5) - 1:
                time.sleep(random.uniform(1, 2))
                
        except Exception as e:
            logger.error(f"Error processing file {file_data.get('server_filename', 'unknown')}: {str(e)}")
            continue
    
    return results

@app.route('/api', methods=['GET'])
def api_handler():
    """Main API endpoint"""
    start_time = time.time()
    url = None
    
    try:
        url = request.args.get('url')
        if not url:
            return jsonify({
                "status": "error",
                "message": "URL parameter is required. Developed by @Farooq_is_king. Join @OPLEECH_WD for updates.",
                "usage": "/api?url=YOUR_TERABOX_SHARE_URL"
            }), 400
        
        logger.info(f"API request for URL: {url}")
        
        # Run in thread pool to avoid blocking
        future = executor.submit(fetch_download_links, url)
        files = future.result(timeout=60)
        
        if not files:
            return jsonify({
                "status": "error",
                "message": "No files found in the shared link",
                "url": url
            }), 404
        
        # Process files
        cookies = load_cookies()
        future = executor.submit(process_files, files, cookies)
        results = future.result(timeout=120)  # Increased timeout for processing
        
        if not results:
            return jsonify({
                "status": "error",
                "message": "Could not process any files",
                "url": url
            }), 500
        
        return jsonify({
            "status": "success",
            "url": url,
            "files": results,
            "processing_time": f"{time.time() - start_time:.2f} seconds",
            "file_count": len(results),
            "total_files": len(files),
            "developer": "@Farooq_is_king",
            "channel": "@OPLEECH_WD"
        })
    
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "url": url or "Not provided",
            "processing_time": f"{time.time() - start_time:.2f} seconds"
        }), 500

@app.route('/')
def home():
    """Home endpoint"""
    data = {
        "status": "Running ✅",
        "developer": "@Farooq_is_king",
        "channel": "@Opleech_WD",
        "version": "3.1.0",
        "endpoints": {
            "/api": "GET with ?url=TERABOX_SHARE_URL parameter",
            "/health": "Service health check"
        },
        "usage_example": "/api?url=https://terabox.com/s/1xxxxxxxxxxxxxxx",
        "note": "Fixed direct download link resolution"
    }
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2), 
        mimetype='application/json'
    )

@app.route('/health')
def health_check():
    """Health check endpoint"""
    cookies = load_cookies()
    data = {
        "status": "healthy" if cookies else "warning",
        "cookies_loaded": len(cookies),
        "developer": "@Farooq_is_king",
        "channel": "@Opleech_WD",
        "timestamp": int(time.time())
    }
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2), 
        mimetype='application/json'
    )

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "error",
        "message": "Endpoint not found",
        "available_endpoints": ["/", "/api", "/health"]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == '__main__':
    # Ensure cookies file exists
    if not os.path.exists(COOKIES_FILE):
        logger.warning(f"Creating empty cookies file: {COOKIES_FILE}")
        with open(COOKIES_FILE, 'w') as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write("# Place your TeraBox cookies here\n")
    
    port = int(os.environ.get("PORT", PORT))
    logger.info(f"Starting TeraBox API server on port {port}")
    logger.info(f"Cookies loaded: {len(load_cookies())}")
    
    app.run(
        host='0.0.0.0', 
        port=port, 
        debug=False,
        threaded=True,
        use_reloader=False
    )
