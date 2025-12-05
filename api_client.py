import requests
from flask import current_app
from werkzeug.exceptions import Unauthorized, Forbidden, InternalServerError

from .auth import get_auth_credentials

def fetch_cluster_name(username: str, password: str) -> str:
    """Fetches the cluster name """
    base_url = current_app.config['API_BASE_URL'].rstrip('/')
    url = f"{base_url}/clusters"
    query_params = "?fields=Clusters/cluster_id&minimal_response=true"
    full_url = url + query_params
    
    headers = {}
    try:
        auth_string = f"-u {username}:{password}"
        header_string = ' '.join([f'-H "{key}: {value}"' for key, value in headers.items()])
        curl_command = f"curl -i {auth_string} {header_string} \"{full_url}\""
        current_app.logger.info("-" * 50)
        current_app.logger.info(f"DEBUG: Executing Cluster API Request (cURL Equivalent):")
        current_app.logger.info(curl_command)
        current_app.logger.info("-" * 50)
        
    except Exception as log_e:
        current_app.logger.warning(f"Failed to generate cURL debug string: {log_e}")

    try:
        response = requests.get(
            full_url, 
            auth=(username, password), 
            headers=headers, 
            timeout=10
        )
        response.raise_for_status() 
        data = response.json()
        
        if data.get('items') and len(data['items']) > 0:
            first_item = data['items'][0]
            cluster_data = first_item.get('Clusters')
            
            if cluster_data:
                cluster_name = cluster_data.get('cluster_name')
                if cluster_name:
                    current_app.logger.info(f"Successfully fetched cluster name: {cluster_name}")
                    return cluster_name
        
        current_app.logger.error("API response for cluster name was empty or malformed.")
        raise InternalServerError("Could not find cluster name in API response.")
    
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        current_app.logger.error(f"HTTP Error during cluster fetch. Status: {status_code}. Response: {e.response.text}")
        
        if status_code == 401:
             raise Unauthorized("Authentication failed for cluster list API. (401)")
        if status_code == 403:
             raise Forbidden("User lacks permission to list clusters. (403)")
        
        raise InternalServerError(f"Upstream API Error {status_code} during cluster fetch: {e.response.text}")

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Failed to connect to the upstream API to get cluster name: {e}")
        raise InternalServerError("Failed to connect to the upstream API to get cluster name.")
    
def check_upstream_authorization(username: str, password: str) -> bool:
    """Verifies credentials against an upstream user endpoint."""
    fields = f"{current_app.config['API_BASE_URL'].rstrip('/')}/users"
    try:
        response = requests.get(fields, auth=(username, password), timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Upstream authorization check failed: {e}")
        return False

def get_api_data(endpoint_path, query_params=""):
    """
    Generic function to fetch data from the upstream API.
    Uses cached credentials for basic auth.
    """
    username, password = get_auth_credentials()
    if not username or not password:
        raise Unauthorized("Credentials not set in request context.")
    
    base_url = current_app.config['API_BASE_URL'].rstrip('/')
    cluster_name = current_app.config['CLUSTER_NAME']

    if not cluster_name:
         current_app.logger.error("CLUSTER_NAME is not set in app config. Please login first.")
         raise InternalServerError("Cluster name not initialized. Please ensure login was successful.")
    
    if endpoint_path.startswith("stacks/") or endpoint_path.startswith("stack_versions"):
        url = f"{base_url}/{endpoint_path.lstrip('/')}{query_params}"
    elif endpoint_path.startswith('/'):
        url = f"{base_url}/clusters/{cluster_name}{endpoint_path}{query_params}"
    else:
        url = f"{base_url}/clusters/{cluster_name}/{endpoint_path}{query_params}"
        
    try:
        response = requests.get(url, auth=(username, password))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        current_app.logger.warning(f"API request failed with status {status_code}: {e.response.text}")
        if status_code == 401 or status_code == 403:
            raise Forbidden("Unauthorized to access the upstream resource.")
        raise InternalServerError(f"Upstream API Error: {status_code}")
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Request failed: {e}")
        raise InternalServerError("Failed to connect to the upstream API.")