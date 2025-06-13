import os
from flask import Flask, request, jsonify, Response
import json
import aiohttp
import asyncio
import logging
import random
import time
from urllib.parse import parse_qs, urlparse, unquote
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor
import ssl
import certifi

app = Flask(__name__)

# ====== 🇮🇳 ==============
# # © Developer = WOODcraft 
# ========================
# Configuration
COOKIES_FILE = 'cookies.txt'
REQUEST_TIMEOUT = 45
MAX_RETRIES = 5
RETRY_DELAY = 3
PORT = 3000

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize user agent rotator
ua = UserAgent()

# Thread pool for async operations
executor = ThreadPoolExecutor(max_workers=5)

def get_realistic_headers():
    """Generate realistic browser headers"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
    ]
    
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
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
                        domain = parts[0]
                        name = parts[5]
                        value = parts[6]
                        cookies_dict[name] = value
                        logger.debug(f"Loaded cookie: {name}")
        except Exception as e:
            logger.error(f"Error loading cookies: {str(e)}")
    else:
        logger.warning(f"Cookies file {COOKIES_FILE} not found")
    
    logger.info(f"Loaded {len(cookies_dict)} cookies")
    return cookies_dict

def find_between(string, start, end):
    """Extract text between two delimiters with multiple attempts"""
    if not string or not start or not end:
        return None
    
    try:
        start_index = string.find(start)
        if start_index == -1:
            return None
        start_index += len(start)
        end_index = string.find(end, start_index)
        if end_index == -1:
            return None
        result = string[start_index:end_index]
        return result if result else None
    except Exception as e:
        logger.debug(f"Error in find_between: {str(e)}")
        return None

async def create_session_with_cookies(cookies_dict):
    """Create aiohttp session with proper SSL and cookie configuration"""
    # Create SSL context
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    # Create connector with proper settings
    connector = aiohttp.TCPConnector(
        limit=50,
        limit_per_host=10,
        ttl_dns_cache=300,
        use_dns_cache=True,
        ssl=ssl_context,
        enable_cleanup_closed=True,
        force_close=True,
        keepalive_timeout=30
    )
    
    # Create session
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=15)
    session = aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=get_realistic_headers()
    )
    
    # Add cookies to session
    for name, value in cookies_dict.items():
        session.cookie_jar.update_cookies({name: value}, response_url=aiohttp.URL('https://terabox.com'))
    
    return session

async def make_request_with_retries(session, url, method='GET', headers=None, params=None, allow_redirects=True):
    """Make HTTP request with comprehensive retry logic"""
    last_exception = None
    
    for attempt in range(MAX_RETRIES):
        try:
            # Add progressive delay
            if attempt > 0:
                delay = RETRY_DELAY * (2 ** attempt) + random.uniform(1, 3)
                logger.info(f"Waiting {delay:.1f}s before retry {attempt + 1}")
                await asyncio.sleep(delay)
            
            # Refresh headers for each attempt
            request_headers = headers or get_realistic_headers()
            if attempt > 0:
                request_headers['Referer'] = 'https://terabox.com/'
            
            logger.info(f"Attempt {attempt + 1}: {method} {url}")
            
            async with session.request(
                method,
                url,
                headers=request_headers,
                params=params,
                allow_redirects=allow_redirects,
                ssl=False  # Disable SSL verification
            ) as response:
                
                # Handle different status codes
                if response.status == 403:
                    logger.warning(f"Forbidden (403) - attempt {attempt + 1}")
                    if attempt == MAX_RETRIES - 1:
                        raise aiohttp.ClientError("Access forbidden by server")
                    continue
                    
                elif response.status == 429:
                    logger.warning(f"Rate limited (429) - attempt {attempt + 1}")
                    await asyncio.sleep(10 + random.uniform(5, 15))
                    continue
                    
                elif response.status >= 500:
                    logger.warning(f"Server error ({response.status}) - attempt {attempt + 1}")
                    continue
                    
                elif response.status >= 400:
                    logger.error(f"Client error ({response.status})")
                    raise aiohttp.ClientError(f"HTTP {response.status}")
                
                logger.info(f"Success: {response.status} from {url}")
                return response
                
        except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError) as e:
            last_exception = e
            error_type = type(e).__name__
            logger.warning(f"Request failed ({error_type}): {str(e)} - attempt {attempt + 1}")
            
            # Handle specific connection errors
            if "Connection closed" in str(e) or "ServerDisconnectedError" in str(e):
                logger.info("Connection closed by server, creating new session...")
                # Let the caller handle session recreation
                raise e
                
        except Exception as e:
            last_exception = e
            logger.error(f"Unexpected error: {str(e)} - attempt {attempt + 1}")
            
    raise Exception(f"All {MAX_RETRIES} attempts failed. Last error: {str(last_exception)}")

async def extract_tokens_from_page(html_content):
    """Extract required tokens from HTML with multiple methods"""
    tokens = {}
    
    # Try different patterns for jsToken
    js_token_patterns = [
        ('fn%28%22', '%22%29'),
        ('jsToken":"', '"'),
        ('jsToken%22%3A%22', '%22'),
        ('"jsToken":"', '"'),
        ('jsToken=', '&'),
        ('jsToken%3D', '%26')
    ]
    
    for start, end in js_token_patterns:
        token = find_between(html_content, start, end)
        if token:
            tokens['jsToken'] = unquote(token)
            logger.info(f"Found jsToken: {token[:10]}...")
            break
    
    # Try different patterns for logid
    logid_patterns = [
        ('dp-logid=', '&'),
        ('logid":"', '"'),
        ('dplogid":"', '"'),
        ('"logid":"', '"'),
        ('logid=', '&'),
        ('dplogid=', '&')
    ]
    
    for start, end in logid_patterns:
        logid = find_between(html_content, start, end)
        if logid:
            tokens['logid'] = unquote(logid)
            logger.info(f"Found logid: {logid}")
            break
    
    return tokens

async def extract_surl_from_url(url):
    """Extract surl from various TeraBox URL formats"""
    surl = None
    
    # Method 1: from surl parameter
    if 'surl=' in url:
        surl = url.split('surl=')[1].split('&')[0]
    
    # Method 2: from /s/ path
    elif '/s/' in url:
        surl = url.split('/s/')[1].split('?')[0].split('#')[0]
    
    # Method 3: from path segments
    elif 'terabox.com' in url:
        parts = url.split('/')
        for i, part in enumerate(parts):
            if part == 's' and i + 1 < len(parts):
                surl = parts[i + 1].split('?')[0]
                break
    
    if surl:
        surl = unquote(surl)
        logger.info(f"Extracted surl: {surl}")
    
    return surl

async def fetch_download_link_async(url):
    """Main function to fetch download links"""
    cookies = load_cookies()
    if not cookies:
        raise Exception("No cookies found. Please add your TeraBox cookies to cookies.txt")
    
    session = None
    session_recreated = False
    
    try:
        session = await create_session_with_cookies(cookies)
        
        # Make initial request
        logger.info(f"Fetching initial page: {url}")
        
        try:
            response = await make_request_with_retries(session, url)
        except Exception as e:
            if "Connection closed" in str(e) and not session_recreated:
                logger.info("Recreating session due to connection issues...")
                await session.close()
                session = await create_session_with_cookies(cookies)
                session_recreated = True
                response = await make_request_with_retries(session, url)
            else:
                raise
        
        html_content = await response.text()
        final_url = str(response.url)
        
        logger.info(f"Got response from: {final_url}")
        
        # Extract tokens
        tokens = await extract_tokens_from_page(html_content)
        if not tokens.get('jsToken'):
            raise Exception("Could not extract jsToken from page")
        if not tokens.get('logid'):
            raise Exception("Could not extract logid from page")
        
        # Extract surl
        surl = await extract_surl_from_url(final_url)
        if not surl:
            raise Exception(f"Could not extract surl from URL: {final_url}")
        
        # Prepare API request
        api_params = {
            'app_id': '250528',
            'web': '1',
            'channel': 'dubox',
            'clienttype': '0',
            'jsToken': tokens['jsToken'],
            'dplogid': tokens['logid'],
            'page': '1',
            'num': '20',
            'order': 'time',
            'desc': '1',
            'site_referer': final_url,
            'shorturl': surl,
            'root': '1'
        }
        
        # Try different API endpoints
        api_endpoints = [
            'https://www.terabox.com/share/list',
            'https://terabox.com/share/list',
            'https://www.1024tera.com/share/list'
        ]
        
        list_data = None
        for endpoint in api_endpoints:
            try:
                logger.info(f"Trying API endpoint: {endpoint}")
                headers = get_realistic_headers()
                headers['Referer'] = final_url
                
                list_response = await make_request_with_retries(
                    session, 
                    endpoint, 
                    params=api_params,
                    headers=headers
                )
                
                response_text = await list_response.text()
                logger.debug(f"API Response: {response_text[:200]}...")
                
                list_data = await list_response.json()
                
                if list_data.get('errno') == 0 and 'list' in list_data and list_data['list']:
                    logger.info(f"Successfully got {len(list_data['list'])} items from {endpoint}")
                    break
                else:
                    logger.warning(f"API returned error or empty list: {list_data}")
                    
            except Exception as e:
                logger.warning(f"Failed to get data from {endpoint}: {str(e)}")
                continue
        
        if not list_data or 'list' not in list_data or not list_data['list']:
            raise Exception("No files found or API returned empty response")
        
        files = list_data['list']
        logger.info(f"Found {len(files)} files")
        
        # Handle directory case
        if files[0].get('isdir') == 1:
            logger.info("First item is directory, fetching contents...")
            dir_params = api_params.copy()
            dir_params.update({
                'dir': files[0]['path'],
                'order': 'name',
                'desc': '0'
            })
            dir_params.pop('root', None)
            
            for endpoint in api_endpoints:
                try:
                    dir_response = await make_request_with_retries(
                        session, 
                        endpoint, 
                        params=dir_params,
                        headers=headers
                    )
                    dir_data = await dir_response.json()
                    
                    if dir_data.get('errno') == 0 and 'list' in dir_data and dir_data['list']:
                        files = dir_data['list']
                        logger.info(f"Got {len(files)} files from directory")
                        break
                        
                except Exception as e:
                    logger.warning(f"Failed to get directory data from {endpoint}: {str(e)}")
                    continue
        
        return files
        
    finally:
        if session:
            await session.close()

def format_size(size_bytes):
    """Format file size"""
    try:
        size_bytes = int(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    except:
        return "Unknown"

async def process_files(files):
    """Process file list and return formatted data"""
    results = []
    
    for file_data in files[:10]:  # Limit to 10 files to avoid timeout
        try:
            result = {
                "file_name": file_data.get("server_filename", "Unknown"),
                "size": format_size(file_data.get("size", 0)),
                "size_bytes": int(file_data.get("size", 0)),
                "download_url": file_data.get('dlink', ''),
                "is_directory": file_data.get("isdir", 0) == 1,
                "modify_time": file_data.get("server_mtime", 0),
                "path": file_data.get("path", ""),
                "category": file_data.get("category", 0),
                "md5": file_data.get("md5", ""),
                "fs_id": file_data.get("fs_id", "")
            }
            results.append(result)
        except Exception as e:
            logger.error(f"Error processing file: {str(e)}")
            continue
    
    return results

def run_async_function(func, *args):
    """Run async function in new event loop"""
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
                "message": "URL parameter is required",
                "usage": "/api?url=YOUR_TERABOX_SHARE_URL",
                "developer": "@Farooq_is_king"
            }), 400
        
        logger.info(f"Processing URL: {url}")
        
        # Fetch files
        future = executor.submit(run_async_function, fetch_download_link_async, url)
        files = future.result(timeout=120)  # 2 minute timeout
        
        if not files:
            return jsonify({
                "status": "error",
                "message": "No files found in the shared link",
                "url": url
            }), 404
        
        # Process files
        future = executor.submit(run_async_function, process_files, files)
        results = future.result(timeout=30)
        
        if not results:
            return jsonify({
                "status": "error",
                "message": "Could not process files",
                "url": url
            }), 500
        
        return jsonify({
            "status": "success",
            "url": url,
            "files": results,
            "processing_time": f"{time.time() - start_time:.2f} seconds",
            "file_count": len(results),
            "total_found": len(files),
            "developer": "@Farooq_is_king",
            "channel": "@OPLEECH_WD"
        })
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"API Error: {error_msg}")
        
        # Provide more specific error messages
        if "Connection closed" in error_msg:
            error_msg = "Connection blocked by TeraBox. Please try again later or check your cookies."
        elif "jsToken" in error_msg:
            error_msg = "Could not extract authentication token. The link might be invalid or expired."
        elif "surl" in error_msg:
            error_msg = "Invalid TeraBox share URL format."
        elif "cookies" in error_msg.lower():
            error_msg = "Authentication failed. Please update your cookies in cookies.txt file."
        
        return jsonify({
            "status": "error",
            "message": error_msg,
            "url": url or "Not provided",
            "processing_time": f"{time.time() - start_time:.2f} seconds"
        }), 500

@app.route('/')
def home():
    """Home endpoint"""
    cookies_count = len(load_cookies())
    data = {
        "status": "Running ✅",
        "cookies_loaded": cookies_count,
        "developer": "@Farooq_is_king",
        "channel": "@Opleech_WD",
        "version": "3.0.0",
        "endpoints": {
            "/api": "GET with ?url=TERABOX_SHARE_URL parameter",
            "/health": "Service health check"
        },
        "example": "/api?url=https://terabox.com/s/1xxxxxxxxxxxxxxx",
        "note": "Make sure to add your TeraBox cookies to cookies.txt file"
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
        "status": "healthy" if cookies else "warning - no cookies",
        "cookies_loaded": len(cookies),
        "developer": "@Farooq_is_king",
        "channel": "@Opleech_WD",
        "timestamp": int(time.time()),
        "cookies_file_exists": os.path.exists(COOKIES_FILE)
    }
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2), 
        mimetype='application/json'
    )

if __name__ == '__main__':
    # Create cookies file with your provided cookies
    if not os.path.exists(COOKIES_FILE):
        logger.info(f"Creating cookies file: {COOKIES_FILE}")
        with open(COOKIES_FILE, 'w', encoding='utf-8') as f:
            cookies_content = """# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This file was generated by Cookie-Editor
www.terabox.com	FALSE	/	FALSE	1749810564	csrfToken	2Hxl7ivQ0wozxbZ2Rn7eqnx2
.terabox.com	TRUE	/	FALSE	1781260112	PANWEB	1
.terabox.com	TRUE	/	FALSE	1784284123	_ga_RSNVN63CM3	GS2.1.s1749724117$o1$g0$t1749724123$j54$l0$h0
.terabox.com	TRUE	/	FALSE	1783420120	ttcsid_CE7B8VRC77U8BHMEOA70	1749724120199::iF5GM4rKi3IjZ5feRUKn.1.1749724120443
.terabox.com	TRUE	/	FALSE	1754908113	browserid	KROj7d9UwI5Pw2vdffN1B44Zyig8d1mozx1k0-i00LwdXSM-PjE69bg3EFg=
.terabox.com	TRUE	/	FALSE	1784284128	_ga	GA1.1.1625740447.1749724115
.terabox.com	TRUE	/	FALSE	1784284146	_ga_06ZNKL8C2E	GS2.1.s1749724128$o1$g0$t1749724146$j42$l0$h0
.terabox.com	TRUE	/	FALSE	1749810564	ab_ymg_result	{"data":"e3bb3a4a3056f5492d5a25263f4a4363fe5fbb534801052e7cbe40f109eef7ee564f47086f774b1c4b339a70cb327fd021bd2e06f6890607c944e89b3fea8b49400eff6d88e0a4f8d71b718438879f8af439910758c4641097e0ef677b5d9d15a508a906b70f6e789db78f81193fac2942db6a577d194552d1e3d91aee3bf959","key_id":"66","sign":"e21a298f"}
.terabox.com	TRUE	/	FALSE	1784284124	__bid_n	19763af2cc63e91f3f4207
.terabox.com	TRUE	/	FALSE	1757500120	_fbp	fb.1.1749724120016.853320119361117259
.terabox.com	TRUE	/	FALSE	1784284123	_ga_HSVH9T016H	GS2.1.s1749724114$o1$g0$t1749724123$j51$l0$h0
.terabox.com	TRUE	/	FALSE	1783420120	_tt_enable_cookie	1
.terabox.com	TRUE	/	FALSE	1783420120	_ttp	01JXHTYH41K7NQZPXHM1X69X16_.tt.1
#HttpOnly_.terabox.com	TRUE	/	TRUE	1749731325	ab_sr	1.0.1_YjY3YTgwZGNmOTgxMmNkYzhhMDUxY2ZiNjMwMDJmZDJhMjgxYzE4MmU1MmZjZTMzZjYwMjhkNTA2ZmU4MTNkOGEyYzJlYzZjNzE5YjAxOGViMTUzNzYwNzliYTQ5ZTE1ZWEzOTRlMmM2MDJmMmMyYjU3Yjk0NmNiYmJlNTgyYTYwMzc2NzY5MDkzNTJiYmVlMzVjZWJiZmI0MDYwODVhZg==
.terabox.com	TRUE	/	FALSE	1752316123	lang	en
www.terabox.com	FALSE	/	FALSE	1752316125	ndut_fmt	AEBC28755B1F37F42AC12EB2335DF94B8D331D881FABE489DE4A4A3DF731D85C
.terabox.com	TRUE	/	FALSE	1781260113	TSID	ery6ht8Q6T8jrnwh5tVsvEl8yKUhldKD
.terabox.com	TRUE	/	FALSE	1783420120	ttcsid	1749724120200::nE_E7BZoA7O73JYhqlFd.1.1749724120200"""
            f.write(cookies_content)
    
    port = int(os.environ.get("PORT", PORT))
    logger.info(f"Starting TeraBox API server on port {port}")
    logger.info(f"Cookies loaded: {len(load_cookies())}")
    
    app.run(
        host='0.0.0.0', 
        port=port, 
        debug=False,
        threaded=True
    )
