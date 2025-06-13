import os
from flask import Flask, request, jsonify, Response
import json
import aiohttp
import asyncio
import logging
import random
import time
from urllib.parse import parse_qs, urlparse
from fake_useragent import UserAgent
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

# Initialize user agent rotator
ua = UserAgent()

# Thread pool for async operations
executor = ThreadPoolExecutor(max_workers=10)

def get_random_headers():
    """Generate random headers for requests"""
    headers = {
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'Referer': 'https://terafileshare.com/'
    }
    return headers

def load_cookies():
    """Load cookies from Netscape format file"""
    cookies_dict = {}
    if os.path.exists(COOKIES_FILE):
        try:
            with open(COOKIES_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        # Netscape format: domain, flag, path, secure, expiration, name, value
                        name = parts[5]
                        value = parts[6]
                        cookies_dict[name] = value
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

async def make_request(session, url, method='GET', headers=None, params=None, allow_redirects=True):
    """Make HTTP request with retry logic"""
    retry_count = 0
    last_exception = None
    
    while retry_count < MAX_RETRIES:
        try:
            current_headers = headers or get_random_headers()
            
            # Add random delay to avoid rate limiting
            if retry_count > 0:
                await asyncio.sleep(random.uniform(1, 3))
            
            async with session.request(
                method,
                url,
                headers=current_headers,
                params=params,
                allow_redirects=allow_redirects
            ) as response:
                if response.status == 403:
                    logger.warning(f"Blocked by server (403), retrying... (attempt {retry_count + 1})")
                    retry_count += 1
                    await asyncio.sleep(RETRY_DELAY * (retry_count + 1))
                    continue
                elif response.status == 429:
                    logger.warning(f"Rate limited (429), retrying... (attempt {retry_count + 1})")
                    retry_count += 1
                    await asyncio.sleep(RETRY_DELAY * (retry_count + 2))
                    continue
                
                response.raise_for_status()
                return response
                
        except aiohttp.ClientConnectionError as e:
            logger.warning(f"Connection error: {str(e)}, retrying... (attempt {retry_count + 1})")
            retry_count += 1
            last_exception = e
            await asyncio.sleep(RETRY_DELAY * (retry_count + 1))
        except asyncio.TimeoutError as e:
            logger.warning(f"Request timeout, retrying... (attempt {retry_count + 1})")
            retry_count += 1
            last_exception = e
            await asyncio.sleep(RETRY_DELAY * (retry_count + 1))
        except Exception as e:
            logger.warning(f"Request failed: {str(e)}, retrying... (attempt {retry_count + 1})")
            retry_count += 1
            last_exception = e
            await asyncio.sleep(RETRY_DELAY * (retry_count + 1))
    
    raise Exception(f"Max retries exceeded. Last error: {str(last_exception)}")

async def fetch_download_link_async(url):
    """Fetch download links from TeraBox URL"""
    try:
        cookies = load_cookies()
        if not cookies:
            raise Exception("No cookies found. Please provide valid cookies in cookies.txt file.")
        
        # Create cookie jar from loaded cookies
        cookie_jar = aiohttp.CookieJar()
        for name, value in cookies.items():
            cookie_jar.update_cookies({name: value})
            
        # Configure connector with proper settings
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            keepalive_timeout=30,
            enable_cleanup_closed=True,
            force_close=False,
            ssl=False
        )
            
        # Configure timeout
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=10)
            
        async with aiohttp.ClientSession(
            cookie_jar=cookie_jar,
            connector=connector,
            timeout=timeout,
            headers=get_random_headers()
        ) as session:
            
            # First request to get the initial page
            logger.info(f"Making initial request to: {url}")
            response = await make_request(session, url)
            response_data = await response.text()
            
            # Extract tokens with multiple fallback methods
            js_token = (
                find_between(response_data, 'fn%28%22', '%22%29') or
                find_between(response_data, 'jsToken":"', '"') or
                find_between(response_data, 'jsToken%22%3A%22', '%22')
            )
            
            log_id = (
                find_between(response_data, 'dp-logid=', '&') or
                find_between(response_data, 'logid":"', '"') or
                find_between(response_data, 'dplogid":"', '"')
            )
            
            if not js_token:
                logger.error("Could not extract js_token from response")
                raise Exception("Could not extract required jsToken from the page")
            
            if not log_id:
                logger.error("Could not extract log_id from response")
                raise Exception("Could not extract required logid from the page")
            
            logger.info(f"Extracted tokens - jsToken: {js_token[:10]}..., logid: {log_id}")
            
            # Parse surl from final URL (after redirects)
            request_url = str(response.url)
            surl = None
            
            # Try multiple methods to extract surl
            if 'surl=' in request_url:
                surl = request_url.split('surl=')[1].split('&')[0]
            elif '/s/' in request_url:
                surl = request_url.split('/s/')[1].split('?')[0]
            
            if not surl:
                logger.error(f"Could not extract surl from URL: {request_url}")
                raise Exception("Could not extract surl from URL")
            
            logger.info(f"Extracted surl: {surl}")
            
            # Prepare API parameters
            params = {
                'app_id': '250528',
                'web': '1',
                'channel': 'dubox',
                'clienttype': '0',
                'jsToken': js_token,
                'dplogid': log_id,
                'page': '1',
                'num': '20',
                'order': 'time',
                'desc': '1',
                'site_referer': request_url,
                'shorturl': surl,
                'root': '1'
            }
            
            # Try multiple API endpoints
            api_endpoints = [
                'https://www.1024tera.com/share/list',
                'https://www.terabox.com/share/list',
                'https://terabox.com/share/list'
            ]
            
            list_data = None
            for endpoint in api_endpoints:
                try:
                    logger.info(f"Trying API endpoint: {endpoint}")
                    list_response = await make_request(session, endpoint, params=params)
                    list_data = await list_response.json()
                    if 'list' in list_data and list_data['list']:
                        logger.info(f"Successfully got data from {endpoint}")
                        break
                except Exception as e:
                    logger.warning(f"Failed to get data from {endpoint}: {str(e)}")
                    continue
            
            if not list_data or 'list' not in list_data or not list_data['list']:
                raise Exception("No files found in the shared link")
            
            logger.info(f"Found {len(list_data['list'])} items")
            
            # Handle directories
            if list_data['list'][0].get('isdir') == 1 or list_data['list'][0].get('isdir') == "1":
                logger.info("First item is a directory, fetching directory contents")
                dir_params = params.copy()
                dir_params.update({
                    'dir': list_data['list'][0]['path'],
                    'order': 'name',
                    'desc': '0'
                })
                dir_params.pop('root', None)
                
                for endpoint in api_endpoints:
                    try:
                        dir_response = await make_request(session, endpoint, params=dir_params)
                        dir_data = await dir_response.json()
                        if 'list' in dir_data and dir_data['list']:
                            logger.info(f"Successfully got directory data from {endpoint}")
                            return dir_data['list']
                    except Exception as e:
                        logger.warning(f"Failed to get directory data from {endpoint}: {str(e)}")
                        continue
                
                raise Exception("No files found in the directory")
            
            return list_data['list']
    
    except Exception as e:
        logger.error(f"Error in fetch_download_link_async: {str(e)}")
        raise

async def get_direct_link(session, dlink):
    """Get direct download link by following redirects"""
    try:
        if not dlink:
            return ""
            
        # Add random delay
        await asyncio.sleep(random.uniform(0.2, 0.8))
        
        # Make a simple GET request without following redirects
        async with session.get(dlink, allow_redirects=False) as response:
            if 300 <= response.status < 400 and 'Location' in response.headers:
                return response.headers['Location']
            elif response.status == 200:
                return dlink
        
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

async def process_file(session, file_data):
    """Process individual file data"""
    try:
        # Get direct link
        direct_link = await get_direct_link(session, file_data.get('dlink', ''))
        
        return {
            "file_name": file_data.get("server_filename", "Unknown"),
            "size": format_size(file_data.get("size", 0)),
            "size_bytes": int(file_data.get("size", 0)),
            "download_url": file_data.get('dlink', ''),
            "direct_download_url": direct_link,
            "is_directory": file_data.get("isdir", 0) == 1 or file_data.get("isdir", "0") == "1",
            "modify_time": file_data.get("server_mtime", 0),
            "thumbnails": file_data.get("thumbs", {}),
            "path": file_data.get("path", ""),
            "category": file_data.get("category", 0)
        }
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        return None

def run_async_function(func, *args):
    """Run async function in thread pool"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(func(*args))
    finally:
        loop.close()

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
        
        logger.info(f"Processing URL: {url}")
        
        # Run async function in thread pool
        future = executor.submit(run_async_function, fetch_download_link_async, url)
        files = future.result(timeout=60)  # 60 second timeout
        
        if not files:
            return jsonify({
                "status": "error",
                "message": "No files found in the shared link",
                "url": url
            }), 404
        
        # Process files
        async def process_all_files():
            cookies = load_cookies()
            cookie_jar = aiohttp.CookieJar()
            for name, value in cookies.items():
                cookie_jar.update_cookies({name: value})
            
            # Configure connector properly
            connector = aiohttp.TCPConnector(
                limit=30,
                limit_per_host=5,
                keepalive_timeout=30,
                enable_cleanup_closed=True,
                force_close=False,
                ssl=False
            )
            
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=10)
                
            async with aiohttp.ClientSession(
                cookie_jar=cookie_jar,
                connector=connector,
                timeout=timeout,
                headers=get_random_headers()
            ) as session:
                results = []
                
                # Process files sequentially to avoid overwhelming the server
                for file in files[:10]:  # Limit to first 10 files
                    try:
                        processed = await process_file(session, file)
                        if processed:
                            results.append(processed)
                        # Add delay between file processing
                        await asyncio.sleep(0.5)
                    except Exception as e:
                        logger.error(f"Error processing file {file.get('server_filename', 'unknown')}: {str(e)}")
                        continue
                
                return results
        
        future = executor.submit(run_async_function, process_all_files)
        results = future.result(timeout=90)  # 90 second timeout
        
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
        "version": "2.0.0",
        "endpoints": {
            "/api": "GET with ?url=TERABOX_SHARE_URL parameter",
            "/health": "Service health check"
        },
        "usage_example": "/api?url=https://terabox.com/s/1xxxxxxxxxxxxxxx"
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
