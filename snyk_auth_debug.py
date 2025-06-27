class SnykAPIClient:
    """Client for interacting with Snyk REST API with enhanced authentication debugging"""
    
    def __init__(self, api_token: str, org_id: str, base_url: str = "https://api.snyk.io"):
        self.api_token = api_token
        self.org_id = org_id
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Set up authentication headers - try different formats
        self._setup_authentication()
        
        # Configure SSL verification
        try:
            self.session.verify = certifi.where()
        except:
            print("Warning: SSL verification disabled due to certificate issues")
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('snyk_utility.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Test authentication on initialization
        self._test_authentication()
    
    def _setup_authentication(self):
        """Set up authentication headers with different token formats"""
        # Try the standard token format first
        self.session.headers.update({
            'Authorization': f'token {self.api_token}',
            'Content-Type': 'application/vnd.api+json',
            'Accept': 'application/vnd.api+json'
        })
    
    def _test_authentication(self):
        """Test if authentication is working"""
        try:
            self.logger.info("Testing authentication...")
            response = self._make_request('GET', f'/rest/orgs/{self.org_id}')
            self.logger.info("✅ Authentication successful")
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                self.logger.error("❌ 401 Authentication failed")
                self._try_alternative_auth_formats()
            else:
                self.logger.error(f"❌ Authentication test failed with status {e.response.status_code}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Authentication test failed: {e}")
            return False
    
    def _try_alternative_auth_formats(self):
        """Try different authentication header formats"""
        auth_formats = [
            f'Bearer {self.api_token}',
            f'Token {self.api_token}',
            self.api_token
        ]
        
        for auth_format in auth_formats:
            self.logger.info(f"Trying auth format: {auth_format[:20]}...")
            self.session.headers.update({'Authorization': auth_format})
            
            try:
                response = self._make_request('GET', f'/rest/orgs/{self.org_id}')
                self.logger.info(f"✅ Authentication successful with format: {auth_format[:20]}...")
                return True
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    self.logger.debug(f"❌ 401 with format: {auth_format[:20]}...")
                    continue
                else:
                    self.logger.error(f"❌ Non-401 error with format {auth_format[:20]}...: {e.response.status_code}")
            except Exception as e:
                self.logger.debug(f"❌ Exception with format {auth_format[:20]}...: {e}")
        
        self.logger.error("❌ All authentication formats failed")
        return False
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make an API request with enhanced error handling and debugging"""
        url = f"{self.base_url}{endpoint}"
        
        # Add debug logging for requests
        self.logger.debug(f"Making {method} request to: {url}")
        self.logger.debug(f"Headers: {dict(self.session.headers)}")
        
        max_retries = 3
        backoff_factor = 1
        
        for attempt in range(max_retries):
            try:
                response = self.session.request(method, url, **kwargs)
                
                # Log response details for debugging
                self.logger.debug(f"Response status: {response.status_code}")
                self.logger.debug(f"Response headers: {dict(response.headers)}")
                
                if response.status_code == 401:
                    self.logger.error(f"401 Unauthorized for {method} {endpoint}")
                    self.logger.error(f"Response body: {response.text[:500]}")
                    # Don't retry 401 errors - they won't get better
                    response.raise_for_status()
                
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    self.logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    # Don't retry 401 errors
                    raise
                elif attempt == max_retries - 1:
                    self.logger.error(f"Request failed after {max_retries} attempts: {e}")
                    self.logger.error(f"Final response body: {e.response.text[:500]}")
                    raise
                
                wait_time = backoff_factor * (2 ** attempt)
                self.logger.warning(f"Request failed, retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    self.logger.error(f"Request failed after {max_retries} attempts: {e}")
                    raise
                
                wait_time = backoff_factor * (2 ** attempt)
                self.logger.warning(f"Request failed, retrying in {wait_time} seconds...")
                time.sleep(wait_time)
        
        raise Exception("Max retries exceeded")
    
    def trigger_project_test(self, project_id: str) -> bool:
        """Trigger a test/rescan for a specific project using REST API with better error handling"""
        self.logger.info(f"Triggering test for project {project_id}")
        
        # First, verify we can access the project
        try:
            self.logger.debug(f"Verifying access to project {project_id}")
            project_response = self._make_request('GET', f'/rest/orgs/{self.org_id}/projects/{project_id}')
            self.logger.debug(f"✅ Project {project_id} is accessible")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.logger.error(f"❌ Project {project_id} not found (404)")
                return False
            elif e.response.status_code == 401:
                self.logger.error(f"❌ Unauthorized access to project {project_id} (401)")
                return False
            else:
                self.logger.error(f"❌ Error accessing project {project_id}: {e.response.status_code}")
                return False
        
        # Try different REST endpoints for triggering tests
        test_endpoints = [
            # Standard scan endpoint
            {
                'method': 'POST',
                'endpoint': f'/rest/orgs/{self.org_id}/projects/{project_id}/scans',
                'data': None,
                'description': 'Project scans endpoint'
            },
            # Issues test endpoint
            {
                'method': 'POST', 
                'endpoint': f'/rest/orgs/{self.org_id}/projects/{project_id}/issues/test',
                'data': None,
                'description': 'Issues test endpoint'
            },
            # Generic scans endpoint with project reference
            {
                'method': 'POST',
                'endpoint': f'/rest/orgs/{self.org_id}/scans',
                'data': {
                    'data': {
                        'type': 'scan',
                        'attributes': {
                            'project_id': project_id
                        }
                    }
                },
                'description': 'Generic scans endpoint'
            }
        ]
        
        for endpoint_config in test_endpoints:
            try:
                self.logger.info(f"Trying {endpoint_config['description']}: {endpoint_config['endpoint']}")
                
                kwargs = {}
                if endpoint_config['data']:
                    kwargs['json'] = endpoint_config['data']
                
                response = self._make_request(
                    endpoint_config['method'],
                    endpoint_config['endpoint'],
                    **kwargs
                )
                
                self.logger.info(f"✅ Successfully triggered test for project {project_id} using {endpoint_config['description']}")
                return True
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    self.logger.error(f"❌ 401 Unauthorized for {endpoint_config['description']}")
                    self.logger.error(f"Response: {e.response.text[:300]}")
                    # Continue to try other endpoints
                elif e.response.status_code == 404:
                    self.logger.warning(f"⚠️  404 Not Found for {endpoint_config['description']}")
                    # Continue to try other endpoints
                elif e.response.status_code == 400:
                    self.logger.warning(f"⚠️  400 Bad Request for {endpoint_config['description']}")
                    self.logger.warning(f"Response: {e.response.text[:300]}")
                    # Continue to try other endpoints
                else:
                    self.logger.error(f"❌ HTTP {e.response.status_code} for {endpoint_config['description']}")
                    self.logger.error(f"Response: {e.response.text[:300]}")
            except Exception as e:
                self.logger.error(f"❌ Exception for {endpoint_config['description']}: {e}")
        
        self.logger.error(f"❌ All test endpoints failed for project {project_id}")
        return False

    def debug_permissions(self):
        """Debug API permissions and accessible endpoints"""
        self.logger.info("=== DEBUGGING API PERMISSIONS ===")
        
        test_endpoints = [
            ('GET', f'/rest/orgs/{self.org_id}', 'Organization info'),
            ('GET', f'/rest/orgs/{self.org_id}/projects', 'List projects'),
            ('GET', f'/rest/self', 'User info'),
            ('GET', f'/rest/orgs/{self.org_id}/issues', 'List issues'),
        ]
        
        for method, endpoint, description in test_endpoints:
            try:
                response = self._make_request(method, endpoint)
                self.logger.info(f"✅ {description}: HTTP {response.status_code}")
            except requests.exceptions.HTTPError as e:
                self.logger.error(f"❌ {description}: HTTP {e.response.status_code}")
                if e.response.status_code == 401:
                    self.logger.error(f"   Unauthorized - check API token permissions")
                elif e.response.status_code == 403:
                    self.logger.error(f"   Forbidden - insufficient permissions")
            except Exception as e:
                self.logger.error(f"❌ {description}: {e}")


# Add this method to the SnykUtility class
def debug_api_access(self):
    """Debug API access and permissions"""
    print("\n=== DEBUGGING API ACCESS ===")
    
    # Check if API token format is correct
    if not self.client.api_token:
        print("❌ No API token provided")
        return
    
    # API tokens should typically be UUIDs
    if len(self.client.api_token) != 36 or self.client.api_token.count('-') != 4:
        print(f"⚠️  API token format looks unusual (length: {len(self.client.api_token)})")
        print("   Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    
    # Check org ID format
    if not self.client.org_id:
        print("❌ No organization ID provided")
        return
    
    if len(self.client.org_id) != 36 or self.client.org_id.count('-') != 4:
        print(f"⚠️  Organization ID format looks unusual (length: {len(self.client.org_id)})")
        print("   Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    
    # Run permission debugging
    self.client.debug_permissions()