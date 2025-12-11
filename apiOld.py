from flask import Flask, request, jsonify, request_started, make_response
from flask_cors import CORS
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import jwt
import datetime

app = Flask(__name__)

CORS(app, supports_credentials=True, origins="*", allow_headers=["Content-Type", "Authorization"])

base_url = "http://10.10.6.40:8080/api/v1/"
cluster_name = "OBDP_STG"
username = ""
password = ""
    
# General function to check token for API request
@app.before_request
def check_token():
    global username, password
    
    if request.endpoint == 'login':
        return
    
    if request.method != 'OPTIONS': 
        auth_header = request.headers.get('Authorization')        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
                decoded_data = jwt.decode(token, options={"verify_signature": False})   
                if 'exp' not in decoded_data:
                    return make_response(jsonify({"message": "Expired token"}), 400)
                else :
                    decoded_bytes_time = decoded_data['exp']
                    now = int(datetime.datetime.now().timestamp())
                    if decoded_bytes_time < now:
                        return make_response(jsonify({"message": "Token has expired"}), 401)             
                if 'key' not in decoded_data:
                    return make_response(jsonify({"message": "Invalid token"}), 400)
                decoded_bytes = base64.b64decode(decoded_data['key'])
                password = decrypt_password(decoded_bytes)
                username = decoded_data.get('username', None)
                if not username:
                    return make_response(jsonify({"message": "Invalid token."}), 400)                
                return
            except jwt.ExpiredSignatureError:
                return make_response(jsonify({"message": "Token has expired"}), 401)
            except jwt.InvalidTokenError:
                return make_response(jsonify({"message": "Invalid token"}), 401)
            except Exception as e:
                return make_response(jsonify({"message": f"Invalid token: {str(e)}"}), 500)
        else:
            return make_response(jsonify({"message": "Not Authorized"}), 401)

# General function to get data from the API
def get_api_data(api_url):
    print(api_url)
    response = requests.get(api_url, auth=(username, password))
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 403:
        return make_response(jsonify({"message": "Unauthorized"}), 403) 
    else:
        return make_response(jsonify({"message": "internal Server Error"}), 500) 
    

# API to get list of hosts
@app.route('/api/hosts', methods=['GET'])
def get_host():    
    fields = f"{base_url}clusters/{cluster_name}/hosts?fields=Hosts/rack_info,Hosts/host_name,Hosts/maintenance_state,Hosts/public_host_name,Hosts/cpu_count,Hosts/ph_cpu_count,alerts_summary,Hosts/host_status,Hosts/host_state,Hosts/last_heartbeat_time,Hosts/ip,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,host_components/HostRoles/stale_configs,host_components/HostRoles/service_name,host_components/HostRoles/display_name,host_components/HostRoles/desired_admin_state,host_components/metrics/dfs/namenode/ClusterId,host_components/metrics/dfs/FSNamesystem/HAState,metrics/disk,metrics/load/load_one,Hosts/total_mem,stack_versions/HostStackVersions,stack_versions/repository_versions/RepositoryVersions/repository_version,stack_versions/repository_versions/RepositoryVersions/id,stack_versions/repository_versions/RepositoryVersions/display_name&minimal_response=true,host_components/logging&page_size=50&from=0&sortBy=Hosts/host_name.asc"
    data = get_api_data(fields)
    return jsonify(data)

# API to get list of hosts at dashboard heatmaps
@app.route('/api/hosts-dashboard', methods=['GET'])
def get_host_dashboard():    
    fields = f"{base_url}clusters/{cluster_name}/hosts?fields=Hosts/rack_info,Hosts/host_name,Hosts/maintenance_state,Hosts/public_host_name,Hosts/cpu_count,Hosts/ph_cpu_count,alerts_summary,Hosts/host_status,Hosts/host_state,Hosts/last_heartbeat_time,Hosts/ip,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,host_components/HostRoles/stale_configs,host_components/HostRoles/service_name,host_components/HostRoles/display_name,host_components/HostRoles/desired_admin_state,host_components/metrics/dfs/namenode/ClusterId,host_components/metrics/dfs/FSNamesystem/HAState,metrics/disk,metrics/load/load_one,Hosts/total_mem,Hosts/os_arch,Hosts/os_type,metrics/cpu/cpu_system,metrics/cpu/cpu_user,metrics/memory/mem_total,metrics/memory/mem_free,stack_versions/HostStackVersions,stack_versions/repository_versions/RepositoryVersions/repository_version,stack_versions/repository_versions/RepositoryVersions/id,stack_versions/repository_versions/RepositoryVersions/display_name&minimal_response=true,host_components/logging"
    data = get_api_data(fields)
    return jsonify(data)

# API to get memory data
@app.route('/api/memory')
def get_memory():
    now = datetime.datetime.now()
    end_time = int(now.timestamp() * 1000)
    select_time = int(request.args.get('selectedTime'))
    time_ago = now - datetime.timedelta(hours=select_time)    
    start_time = int(time_ago.timestamp() * 1000)
    fields = (
        f"{base_url}clusters/{cluster_name}/?fields="
        f"metrics/memory/Buffer._avg[{start_time},{end_time},15],"
        f"metrics/memory/Cache._avg[{start_time},{end_time},15],"
        f"metrics/memory/Share._avg[{start_time},{end_time},15],"
        f"metrics/memory/Swap._avg[{start_time},{end_time},15],"
        f"metrics/memory/Total._avg[{start_time},{end_time},15],"
        f"metrics/memory/Use._avg[{start_time},{end_time},15]"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get network data
@app.route('/api/network')
def get_network():
    now = datetime.datetime.now()
    end_time = int(now.timestamp() * 1000)
    select_time = int(request.args.get('selectedTime'))
    time_ago = now - datetime.timedelta(hours=select_time)    
    start_time = int(time_ago.timestamp() * 1000)
    fields = (
        f"{base_url}clusters/{cluster_name}/?fields="
        f"metrics/network/In._avg[{start_time},{end_time},15],"
        f"metrics/network/Out._avg[{start_time},{end_time},15]"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get cpu data
@app.route('/api/cpu')
def get_cpu():
    now = datetime.datetime.now()
    end_time = int(now.timestamp() * 1000)
    select_time = int(request.args.get('selectedTime'))
    time_ago = now - datetime.timedelta(hours=select_time)    
    start_time = int(time_ago.timestamp() * 1000)
    fields = (
        f"{base_url}clusters/{cluster_name}/?fields="
        f"metrics/cpu/Idle._avg[{start_time},{end_time},15],"
        f"metrics/cpu/Nice._avg[{start_time},{end_time},15]"
        f"metrics/cpu/System._avg[{start_time},{end_time},15]"
        f"metrics/cpu/User._avg[{start_time},{end_time},15]"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get cpu data per host
@app.route('/api/cpu_host')
def get_cpu_host():
    now = datetime.datetime.now()
    end_time = int(now.timestamp() * 1000)
    select_host = request.args.get('host')
    select_time = int(request.args.get('selectedTime'))
    time_ago = now - datetime.timedelta(hours=select_time)    
    start_time = int(time_ago.timestamp() * 1000)
    fields = (
        f"{base_url}clusters/{cluster_name}/hosts/{select_host}?fields="
        f"metrics/cpu/cpu_user._avg[{start_time},{end_time},15],"
        f"metrics/cpu/cpu_wio._avg[{start_time},{end_time},15],"
        f"metrics/cpu/cpu_nice._avg[{start_time},{end_time},15],"
        f"metrics/cpu/cpu_aidle._avg[{start_time},{end_time},15],"
        f"metrics/cpu/cpu_system._avg[{start_time},{end_time},15],"
        f"metrics/cpu/cpu_idle._avg[{start_time},{end_time},15],"
        f"metrics/disk/disk_total._avg[{start_time},{end_time},15],"
        f"metrics/disk/disk_free._avg[{start_time},{end_time},15],"
        f"metrics/load/load_fifteen._avg[{start_time},{end_time},15],"
        f"metrics/load/load_one._avg[{start_time},{end_time},15],"
        f"metrics/load/load_five._avg[{start_time},{end_time},15],"
        f"metrics/memory/swap_free._avg[{start_time},{end_time},15],"
        f"metrics/memory/mem_shared._avg[{start_time},{end_time},15],"
        f"metrics/memory/mem_free._avg[{start_time},{end_time},15],"
        f"metrics/memory/mem_cached._avg[{start_time},{end_time},15],"
        f"metrics/memory/mem_buffers._avg[{start_time},{end_time},15],"
        f"metrics/network/bytes_in._avg[{start_time},{end_time},15],"
        f"metrics/network/bytes_out._avg[{start_time},{end_time},15],"
        f"metrics/network/pkts_in._avg[{start_time},{end_time},15],"
        f"metrics/network/pkts_out._avg[{start_time},{end_time},15],"
        f"metrics/process/proc_total._avg[{start_time},{end_time},15],"
        f"metrics/process/proc_run._avg[{start_time},{end_time},15]"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get load data
@app.route('/api/load')
def get_load():
    now = datetime.datetime.now()
    end_time = int(now.timestamp() * 1000)
    select_time = int(request.args.get('selectedTime'))
    time_ago = now - datetime.timedelta(hours=select_time)    
    start_time = int(time_ago.timestamp() * 1000)
    fields = (
        f"{base_url}clusters/{cluster_name}/?fields="
        f"metrics/load/1-min._avg[{start_time},{end_time},15],"
        f"metrics/load/CPUs._avg[{start_time},{end_time},15]"
        f"metrics/load/Nodes._avg[{start_time},{end_time},15]"
        f"metrics/load/Procs._avg[{start_time},{end_time},15]"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get service info data
@app.route('/api/service-info')
def get_service_info():
    fields = (
        f"{base_url}clusters/{cluster_name}/components/?ServiceComponentInfo/category.in(MASTER,CLIENT)&fields=ServiceComponentInfo/service_name,host_components/HostRoles/display_name,host_components/HostRoles/host_name,host_components/HostRoles/public_host_name,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,host_components/HostRoles/stale_configs,host_components/HostRoles/ha_state,host_components/HostRoles/desired_admin_state,,host_components/metrics/jvm/memHeapUsedM,host_components/metrics/jvm/HeapMemoryMax,host_components/metrics/jvm/HeapMemoryUsed,host_components/metrics/jvm/memHeapCommittedM,host_components/metrics/mapred/jobtracker/trackers_decommissioned,host_components/metrics/cpu/cpu_wio,host_components/metrics/rpc/client/RpcQueueTime_avg_time,host_components/metrics/dfs/FSNamesystem/*,host_components/metrics/dfs/namenode/Version,host_components/metrics/dfs/namenode/LiveNodes,host_components/metrics/dfs/namenode/DeadNodes,host_components/metrics/dfs/namenode/DecomNodes,host_components/metrics/dfs/namenode/TotalFiles,host_components/metrics/dfs/namenode/UpgradeFinalized,host_components/metrics/dfs/namenode/Safemode,host_components/metrics/runtime/StartTime,host_components/metrics/hbase/master/IsActiveMaster,host_components/metrics/hbase/master/MasterStartTime,host_components/metrics/hbase/master/MasterActiveTime,host_components/metrics/hbase/master/AverageLoad,host_components/metrics/master/AssignmentManager/ritCount,host_components/metrics/dfs/namenode/ClusterId&minimal_response=true"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get detail component info data
@app.route('/api/detail-component-info')
def get_detail_component_info():
    fields = (
        f"{base_url}clusters/{cluster_name}/components/?ServiceComponentInfo/component_name=APP_TIMELINE_SERVER|ServiceComponentInfo/component_name=JOURNALNODE|ServiceComponentInfo/component_name=ZKFC|ServiceComponentInfo/category.in(MASTER,CLIENT)&fields=ServiceComponentInfo/service_name,host_components/HostRoles/display_name,host_components/HostRoles/host_name,host_components/HostRoles/public_host_name,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,host_components/HostRoles/stale_configs,host_components/HostRoles/ha_state,host_components/HostRoles/desired_admin_state,,host_components/metrics/jvm/memHeapUsedM,host_components/metrics/jvm/HeapMemoryMax,host_components/metrics/jvm/HeapMemoryUsed,host_components/metrics/jvm/memHeapCommittedM,host_components/metrics/mapred/jobtracker/trackers_decommissioned,host_components/metrics/cpu/cpu_wio,host_components/metrics/rpc/client/RpcQueueTime_avg_time,host_components/metrics/dfs/FSNamesystem/*,host_components/metrics/dfs/namenode/Version,host_components/metrics/dfs/namenode/LiveNodes,host_components/metrics/dfs/namenode/DeadNodes,host_components/metrics/dfs/namenode/DecomNodes,host_components/metrics/dfs/namenode/TotalFiles,host_components/metrics/dfs/namenode/UpgradeFinalized,host_components/metrics/dfs/namenode/Safemode,host_components/metrics/runtime/StartTime,host_components/metrics/hbase/master/IsActiveMaster,host_components/metrics/hbase/master/MasterStartTime,host_components/metrics/hbase/master/MasterActiveTime,host_components/metrics/hbase/master/AverageLoad,host_components/metrics/master/AssignmentManager/ritCount,host_components/metrics/dfs/namenode/ClusterId,host_components/metrics/yarn/Queue,host_components/metrics/yarn/ClusterMetrics/NumActiveNMs,host_components/metrics/yarn/ClusterMetrics/NumLostNMs,host_components/metrics/yarn/ClusterMetrics/NumUnhealthyNMs,host_components/metrics/yarn/ClusterMetrics/NumRebootedNMs,host_components/metrics/yarn/ClusterMetrics/NumDecommissionedNMs&minimal_response=true"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get stack and version
@app.route('/api/stack-version')
def get_stack_version():
    fields = (
        f"{base_url}stacks/ODP/versions/0.2/services?fields="
        "StackServices/*,components/*,components/dependencies/Dependencies/scope,"
        "components/dependencies/Dependencies/service_name,artifacts/Artifacts/artifact_name"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get services stack and version
@app.route('/api/stack-version-services')
def get_stack_version_services():
    fields = (
        f"{base_url}clusters/{cluster_name}/services?fields=ServiceInfo/state,ServiceInfo/maintenance_state&minimal_response=true"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get installed service
@app.route('/api/installed-service')
def get_installed_service():
    fields = (
        f"{base_url}clusters/{cluster_name}/stack_versions?fields=*,repository_versions/*,repository_versions/operating_systems/OperatingSystems/*,repository_versions/operating_systems/repositories"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get list general alerts
@app.route('/api/alert-topbar')
def get_alert_topbar():
    fields = (
        f"{base_url}clusters/{cluster_name}/alerts?fields=Alert/component_name,Alert/definition_id,Alert/definition_name,Alert/host_name,Alert/id,Alert/instance,Alert/label,Alert/latest_timestamp,Alert/maintenance_state,Alert/original_timestamp,Alert/scope,Alert/service_name,Alert/state,Alert/text,Alert/repeat_tolerance,Alert/repeat_tolerance_remaining&Alert/state.in(CRITICAL,WARNING)&Alert/maintenance_state.in(OFF)&from=0&page_size=10"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get list general alerts
@app.route('/api/alerts')
def get_alerts():
    fields = (
        f"{base_url}clusters/{cluster_name}/alerts?fields=*"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get list alert definitions
@app.route('/api/alert-definitions')
def get_alert_definitions():
    fields = (
        f"{base_url}clusters/{cluster_name}/alert_definitions?fields=*"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get list general alerts
@app.route('/api/host_alerts')
def get_host_alerts():
    host_name = request.args.get('host')
    print(host_name)
    fields = (
        f"{base_url}clusters/{cluster_name}/alerts?fields=*&Alert/host_name={host_name}"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get menu service
@app.route('/api/menu')
def get_menu():
    fields = (
        f"{base_url}stacks/ODP/versions/0.2/services?fields=StackServices/"
        "*,components/*,components/dependencies/Dependencies/scope,components/"
        "dependencies/Dependencies/service_name,artifacts/Artifacts/artifact_name"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get accounts data
@app.route('/api/accounts')
def get_accounts():
    fields = (
        f"{base_url}stacks/ODP/versions/0.2?fields=configurations/*,Versions/config_types/*"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get service accounts data
@app.route('/api/service-accounts')
def get_service_accounts():
    fields = (
        f"{base_url}stacks/ODP/versions/0.2/services?StackServices/service_name.in(HDFS,YARN,MAPREDUCE2,TEZ,HIVE,HBASE,SQOOP,ZOOKEEPER,AMBARI_INFRA_SOLR,AMBARI_METRICS,ATLAS,KAFKA,RANGER,SPARK3,ZEPPELIN,AIRFLOW,IMPALA,KUDU,OPENSEARCH,REDIS,HADOOP)&fields=configurations/*,configurations/dependencies/*,StackServices/config_types/*"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get data quicklink for each service
@app.route('/api/quicklink')
def get_quicklink():
    service_name = request.args.get('service')
    fields = (
        f"{base_url}stacks/ODP/versions/0.2/services/{service_name}/quicklinks?QuickLinkInfo/default=true&fields=*"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get load data component services
@app.route('/api/component-services')
def get_components():
    fields = (
        f"{base_url}clusters/{cluster_name}/components/?ServiceComponentInfo/category.in(MASTER,CLIENT)&fields=ServiceComponentInfo/service_name,host_components/HostRoles/display_name,host_components/HostRoles/host_name,host_components/HostRoles/public_host_name,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,host_components/HostRoles/stale_configs,host_components/HostRoles/ha_state,host_components/HostRoles/desired_admin_state,,host_components/metrics/jvm/memHeapUsedM,host_components/metrics/jvm/HeapMemoryMax,host_components/metrics/jvm/HeapMemoryUsed,host_components/metrics/jvm/memHeapCommittedM,host_components/metrics/mapred/jobtracker/trackers_decommissioned,host_components/metrics/cpu/cpu_wio,host_components/metrics/rpc/client/RpcQueueTime_avg_time,host_components/metrics/dfs/FSNamesystem/*,host_components/metrics/dfs/namenode/Version,host_components/metrics/dfs/namenode/LiveNodes,host_components/metrics/dfs/namenode/DeadNodes,host_components/metrics/dfs/namenode/DecomNodes,host_components/metrics/dfs/namenode/TotalFiles,host_components/metrics/dfs/namenode/UpgradeFinalized,host_components/metrics/dfs/namenode/Safemode,host_components/metrics/runtime/StartTime,host_components/metrics/hbase/master/IsActiveMaster,host_components/metrics/hbase/master/MasterStartTime,host_components/metrics/hbase/master/MasterActiveTime,host_components/metrics/hbase/master/AverageLoad,host_components/metrics/master/AssignmentManager/ritCount,host_components/metrics/dfs/namenode/ClusterId&minimal_response=true"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get load config history
@app.route('/api/config-history')
def get_config_history():
    fields = (
        f"{base_url}clusters/{cluster_name}/configurations/service_config_versions?page_size=1000&from=0&sortBy=createtime.desc&fields=service_config_version,user,group_id,group_name,is_current,createtime,service_name,hosts,service_config_version_note,is_cluster_compatible,stack_id&minimal_response=true"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get load config (to edit config ambari metrics)
@app.route('/api/config')
def get_config():
    fields = (
        f"{base_url}clusters/{cluster_name}/configurations/service_config_versions?service_name.in(AMBARI_METRICS,HDFS,ZOOKEEPER,RANGER_KMS,RANGER,YARN,HIVE,KAFKA)&is_current=true"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API to get load data
@app.route('/api/heatmap-hbase')
def get_heatmap_hbase():
    type = int(request.args.get('selectedTime'))
    fields = (
        f"{base_url}clusters/{cluster_name}/services/HBASE/components/HBASE_REGIONSERVER?fields=host_components/metrics/hbase/regionserver/{type}"
    )
    data = get_api_data(fields)
    return jsonify(data)

# API for do login
@app.route('/api/login', methods=['POST'])
def login():
    global username, password
    if request.is_json:
        data = request.get_json()
        username = data.get('username', 'admin')
        password = data.get('password', 'admin')
        if cek_authorization():
            pwd = encrypt_password(password)
            key = base64.b64encode(pwd).decode('utf-8')
            response = {
                'username': username,
                'key': key,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2) 
            }
            encoded_jwt = jwt.encode(response, 'onyxtokenkey', algorithm='HS256')
            response.update({'token': encoded_jwt})
            del response['key']
            return jsonify(response), 200
        else: return make_response(jsonify({"message": "Invalid username/password combination."}), 401)
    else:
        return jsonify({'error': 'Request must be JSON'}), 400

def cek_authorization():
    global username, password
    fields = f"{base_url}users"
    response = requests.get(fields, auth=(username, password))
    if response.status_code == 200:
        return True
    return False

# Method for encrypt password
def encrypt_password(password: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(b"optimasidataonyx"), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_length = 16 - len(password.encode()) % 16
    padded_password = password.encode() + bytes([pad_length]) * pad_length
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
    return iv + encrypted_password

# Method for decrypt password
def decrypt_password(encrypted_password: bytes) -> str:
    iv = encrypted_password[:16]
    encrypted_password_data = encrypted_password[16:]
    cipher = Cipher(algorithms.AES(b"optimasidataonyx"), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password_data) + decryptor.finalize()
    pad_length = decrypted_password[-1]
    decrypted_password = decrypted_password[:-pad_length]
    return decrypted_password.decode()

if __name__ == "__main__":
    app.run(debug=True)
