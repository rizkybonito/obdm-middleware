import datetime

from flask import Blueprint, request, jsonify, make_response, current_app
from werkzeug.exceptions import Unauthorized
import jwt
import base64
from .auth import auth_required, encrypt_password
from .api_client import fetch_cluster_name, get_api_data, check_upstream_authorization
from .config import set_cluster_name_in_config

api_bp = Blueprint('api', __name__, url_prefix='/api')
METRICS_MAP = {
    'memory': ['metrics/memory/Buffer', 'metrics/memory/Cache', 'metrics/memory/Share', 
               'metrics/memory/Swap', 'metrics/memory/Total', 'metrics/memory/Use'],
    'network': ['metrics/network/In', 'metrics/network/Out'],
    'cpu': ['metrics/cpu/Idle', 'metrics/cpu/Nice', 'metrics/cpu/System', 'metrics/cpu/User'],
    'load': ['metrics/load/1-min', 'metrics/load/CPUs', 'metrics/load/Nodes', 'metrics/load/Procs'],
}

def get_time_range_params():
    """Calculates start and end timestamps based on an optional query parameter."""
    now = datetime.datetime.now(datetime.timezone.utc)
    end_time_ms = int(now.timestamp() * 1000)
    
    try:
        select_time_hours = int(request.args.get('selectedTime', 1))
    except ValueError:
        select_time_hours = 1

    time_ago = now - datetime.timedelta(hours=select_time_hours)
    start_time_ms = int(time_ago.timestamp() * 1000)
    
    return start_time_ms, end_time_ms

def build_metrics_fields(base_path, metrics_list, start_time, end_time, interval=15):
    """Builds the query string for fetching metrics."""
    fields = ",".join(f"{metric}._avg[{start_time},{end_time},{interval}]" for metric in metrics_list)
    return f"?fields={fields}"

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request must be JSON'}), 400

    username = data.get('username', current_app.config.get('DEFAULT_USERNAME'))
    password = data.get('password', current_app.config.get('DEFAULT_PASSWORD'))

    if not username or not password:
        return make_response(jsonify({"message": "Username and password required."}), 400)

    if check_upstream_authorization(username, password):
        try:
            cluster_name = fetch_cluster_name(username, password)
            set_cluster_name_in_config(current_app, cluster_name)
            response_cluster_name = cluster_name
        except Exception as e:
            current_app.logger.error(f"Login failed: Could not fetch cluster name after successful authorization: {e}")
            raise Unauthorized("Authorization succeeded, but cluster details could not be retrieved.")
        encrypted_pwd_bytes = encrypt_password(password)
        key_b64 = base64.b64encode(encrypted_pwd_bytes).decode('utf-8')
        payload = {
            'username': username,
            'key': key_b64,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=current_app.config['TOKEN_EXPIRY_HOURS'])
        }
        
        encoded_jwt = jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'username': username,
            'token': encoded_jwt,
            'cluster_name': response_cluster_name,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=current_app.config['TOKEN_EXPIRY_HOURS'])
        }), 200
    else:
        raise Unauthorized("Invalid username/password combination.")

def create_metrics_route(metric_key, endpoint_path=""):
    """Registers a standard metric route."""
    def get_standard_metric_wrapper():
        start_time, end_time = get_time_range_params()
        metrics_list = METRICS_MAP[metric_key]
        query = build_metrics_fields(endpoint_path, metrics_list, start_time, end_time)
        data = get_api_data(endpoint_path, query)
        return jsonify(data)
    wrapped_func = auth_required(get_standard_metric_wrapper)
    wrapped_func.__name__ = f"get_metric_{metric_key}" 
    api_bp.add_url_rule(
        f'/{metric_key}', 
        view_func=wrapped_func,
        methods=['GET'],
    )

create_metrics_route('memory')
create_metrics_route('network')
create_metrics_route('cpu')
create_metrics_route('load')

@api_bp.route('/cpu_host')
@auth_required
def get_cpu_host():
    host_name = request.args.get('host')
    if not host_name:
        return make_response(jsonify({"message": "Missing 'host' query parameter"}), 400)
        
    start_time, end_time = get_time_range_params()
    
    host_metrics = [
        "metrics/cpu/cpu_user", "metrics/cpu/cpu_wio", "metrics/cpu/cpu_nice", 
        "metrics/cpu/cpu_aidle", "metrics/cpu/cpu_system", "metrics/cpu/cpu_idle",
        "metrics/disk/disk_total", "metrics/disk/disk_free", 
        "metrics/load/load_fifteen", "metrics/load/load_one", "metrics/load/load_five",
        "metrics/memory/swap_free", "metrics/memory/mem_shared", "metrics/memory/mem_free",
        "metrics/memory/mem_cached", "metrics/memory/mem_buffers", 
        "metrics/network/bytes_in", "metrics/network/bytes_out", 
        "metrics/network/pkts_in", "metrics/network/pkts_out",
        "metrics/process/proc_total", "metrics/process/proc_run"
    ]
    
    endpoint_path = f"hosts/{host_name}"
    query = build_metrics_fields(endpoint_path, host_metrics, start_time, end_time)
    
    data = get_api_data(endpoint_path, query)
    return jsonify(data)

@api_bp.route('/hosts', methods=['GET'])
@auth_required
def get_host():
    fields = (
        "Hosts/rack_info,Hosts/host_name,Hosts/maintenance_state,Hosts/public_host_name,"
        "Hosts/cpu_count,Hosts/ph_cpu_count,alerts_summary,Hosts/host_status,Hosts/host_state,"
        "Hosts/last_heartbeat_time,Hosts/ip,host_components/HostRoles/state,"
        "host_components/HostRoles/maintenance_state,host_components/HostRoles/stale_configs,"
        "host_components/HostRoles/service_name,host_components/HostRoles/display_name,"
        "host_components/HostRoles/desired_admin_state,host_components/metrics/dfs/namenode/ClusterId,"
        "host_components/metrics/dfs/FSNamesystem/HAState,metrics/disk,metrics/load/load_one,"
        "Hosts/total_mem,stack_versions/HostStackVersions,"
        "stack_versions/repository_versions/RepositoryVersions/repository_version,"
        "stack_versions/repository_versions/RepositoryVersions/id,"
        "stack_versions/repository_versions/RepositoryVersions/display_name&minimal_response=true,"
        "host_components/logging&page_size=50&from=0&sortBy=Hosts/host_name.asc"
    )
    data = get_api_data("hosts", f"?fields={fields}")
    return jsonify(data)

@api_bp.route('/hosts-dashboard', methods=['GET'])
@auth_required
def get_host_dashboard():
    fields = (
        "Hosts/rack_info,Hosts/host_name,Hosts/maintenance_state,Hosts/public_host_name,"
        "Hosts/cpu_count,Hosts/ph_cpu_count,alerts_summary,Hosts/host_status,Hosts/host_state,"
        "Hosts/last_heartbeat_time,Hosts/ip,host_components/HostRoles/state,"
        "host_components/HostRoles/maintenance_state,host_components/HostRoles/stale_configs,"
        "host_components/HostRoles/service_name,host_components/HostRoles/display_name,"
        "host_components/HostRoles/desired_admin_state,host_components/metrics/dfs/namenode/ClusterId,"
        "host_components/metrics/dfs/FSNamesystem/HAState,metrics/disk,metrics/load/load_one,"
        "Hosts/total_mem,Hosts/os_arch,Hosts/os_type,metrics/cpu/cpu_system,metrics/cpu/cpu_user,"
        "metrics/memory/mem_total,metrics/memory/mem_free,stack_versions/HostStackVersions,"
        "stack_versions/repository_versions/RepositoryVersions/repository_version,"
        "stack_versions/repository_versions/RepositoryVersions/id,"
        "stack_versions/repository_versions/RepositoryVersions/display_name&minimal_response=true,"
        "host_components/logging"
    )
    data = get_api_data("hosts", f"?fields={fields}")
    return jsonify(data)

@api_bp.route('/service-info')
@auth_required
def get_service_info():
    fields = (
        "ServiceComponentInfo/service_name,host_components/HostRoles/display_name,host_components/HostRoles/host_name,"
        "host_components/HostRoles/public_host_name,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,"
        "host_components/HostRoles/stale_configs,host_components/HostRoles/ha_state,host_components/HostRoles/desired_admin_state,"
        "host_components/metrics/jvm/memHeapUsedM,host_components/metrics/jvm/HeapMemoryMax,host_components/metrics/jvm/HeapMemoryUsed,"
        "host_components/metrics/jvm/memHeapCommittedM,host_components/metrics/mapred/jobtracker/trackers_decommissioned,"
        "host_components/metrics/cpu/cpu_wio,host_components/metrics/rpc/client/RpcQueueTime_avg_time,"
        "host_components/metrics/dfs/FSNamesystem/*,host_components/metrics/dfs/namenode/Version,"
        "host_components/metrics/dfs/namenode/LiveNodes,host_components/metrics/dfs/namenode/DeadNodes,"
        "host_components/metrics/dfs/namenode/DecomNodes,host_components/metrics/dfs/namenode/TotalFiles,"
        "host_components/metrics/dfs/namenode/UpgradeFinalized,host_components/metrics/dfs/namenode/Safemode,"
        "host_components/metrics/runtime/StartTime,host_components/metrics/hbase/master/IsActiveMaster,"
        "host_components/metrics/hbase/master/MasterStartTime,host_components/metrics/hbase/master/MasterActiveTime,"
        "host_components/metrics/hbase/master/AverageLoad,host_components/metrics/master/AssignmentManager/ritCount,"
        "host_components/metrics/dfs/namenode/ClusterId&minimal_response=true"
    )
    query = f"?ServiceComponentInfo/category.in(MASTER,CLIENT)&fields={fields}"
    data = get_api_data("components", query)
    return jsonify(data)

@api_bp.route('/detail-component-info')
@auth_required
def get_detail_component_info():
    fields = (
        "ServiceComponentInfo/service_name,host_components/HostRoles/display_name,host_components/HostRoles/host_name,"
        "host_components/HostRoles/public_host_name,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,"
        "host_components/HostRoles/stale_configs,host_components/HostRoles/ha_state,host_components/HostRoles/desired_admin_state,"
        "host_components/metrics/jvm/memHeapUsedM,host_components/metrics/jvm/HeapMemoryMax,host_components/metrics/jvm/HeapMemoryUsed,"
        "host_components/metrics/jvm/memHeapCommittedM,host_components/metrics/mapred/jobtracker/trackers_decommissioned,"
        "host_components/metrics/cpu/cpu_wio,host_components/metrics/rpc/client/RpcQueueTime_avg_time,"
        "host_components/metrics/dfs/FSNamesystem/*,host_components/metrics/dfs/namenode/Version,"
        "host_components/metrics/dfs/namenode/LiveNodes,host_components/metrics/dfs/namenode/DeadNodes,"
        "host_components/metrics/dfs/namenode/DecomNodes,host_components/metrics/dfs/namenode/TotalFiles,"
        "host_components/metrics/dfs/namenode/UpgradeFinalized,host_components/metrics/dfs/namenode/Safemode,"
        "host_components/metrics/runtime/StartTime,host_components/metrics/hbase/master/IsActiveMaster,"
        "host_components/metrics/hbase/master/MasterStartTime,host_components/metrics/hbase/master/MasterActiveTime,"
        "host_components/metrics/hbase/master/AverageLoad,host_components/metrics/master/AssignmentManager/ritCount,"
        "host_components/metrics/dfs/namenode/ClusterId,host_components/metrics/yarn/Queue,"
        "host_components/metrics/yarn/ClusterMetrics/NumActiveNMs,host_components/metrics/yarn/ClusterMetrics/NumLostNMs,"
        "host_components/metrics/yarn/ClusterMetrics/NumUnhealthyNMs,host_components/metrics/yarn/ClusterMetrics/NumRebootedNMs,"
        "host_components/metrics/yarn/ClusterMetrics/NumDecommissionedNMs&minimal_response=true"
    )
    query = (
        "?ServiceComponentInfo/component_name=APP_TIMELINE_SERVER|ServiceComponentInfo/component_name=JOURNALNODE|"
        "ServiceComponentInfo/component_name=ZKFC|ServiceComponentInfo/category.in(MASTER,CLIENT)&fields="
        f"{fields}"
    )
    data = get_api_data("components", query)
    return jsonify(data)

@api_bp.route('/stack-version')
@auth_required
def get_stack_version():
    fields = (
        "StackServices/*,components/*,components/dependencies/Dependencies/scope,"
        "components/dependencies/Dependencies/service_name,artifacts/Artifacts/artifact_name"
    )
    data = get_api_data("stacks/ODP/versions/0.2/services", f"?fields={fields}")
    return jsonify(data)

@api_bp.route('/stack-version-services')
@auth_required
def get_stack_version_services():
    fields = "ServiceInfo/state,ServiceInfo/maintenance_state&minimal_response=true"
    data = get_api_data("services", f"?fields={fields}")
    return jsonify(data)

@api_bp.route('/installed-service')
@auth_required
def get_installed_service():
    fields = "*,repository_versions/*,repository_versions/operating_systems/OperatingSystems/*,repository_versions/operating_systems/repositories"
    data = get_api_data("stack_versions", f"?fields={fields}")
    return jsonify(data)

@api_bp.route('/alert-topbar')
@auth_required
def get_alert_topbar():
    fields = (
        "Alert/component_name,Alert/definition_id,Alert/definition_name,Alert/host_name,Alert/id,"
        "Alert/instance,Alert/label,Alert/latest_timestamp,Alert/maintenance_state,Alert/original_timestamp,"
        "Alert/scope,Alert/service_name,Alert/state,Alert/text,Alert/repeat_tolerance,"
        "Alert/repeat_tolerance_remaining"
    )
    query = (
        f"?fields={fields}&Alert/state.in(CRITICAL,WARNING)&Alert/maintenance_state.in(OFF)"
        f"&from=0&page_size=10"
    )
    data = get_api_data("alerts", query)
    return jsonify(data)

@api_bp.route('/alerts')
@auth_required
def get_alerts():
    data = get_api_data("alerts", "?fields=*")
    return jsonify(data)

@api_bp.route('/alert-definitions')
@auth_required
def get_alert_definitions():
    data = get_api_data("alert_definitions", "?fields=*")
    return jsonify(data)

@api_bp.route('/host_alerts')
@auth_required
def get_host_alerts():
    host_name = request.args.get('host')
    if not host_name:
        return make_response(jsonify({"message": "Missing 'host' query parameter"}), 400)
    
    query = f"?fields=*&Alert/host_name={host_name}"
    data = get_api_data("alerts", query)
    return jsonify(data)

@api_bp.route('/menu')
@auth_required
def get_menu():
    fields = (
        "StackServices/*,components/*,components/dependencies/Dependencies/scope,components/"
        "dependencies/Dependencies/service_name,artifacts/Artifacts/artifact_name"
    )
    data = get_api_data("stacks/ODP/versions/0.2/services", f"?fields={fields}") 
    return jsonify(data)


@api_bp.route('/accounts')
@auth_required
def get_accounts():
    fields = "configurations/*,Versions/config_types/*"
    data = get_api_data("stacks/ODP/versions/0.2", f"?fields={fields}")
    return jsonify(data)

@api_bp.route('/service-accounts')
@auth_required
def get_service_accounts():
    fields = "configurations/*,configurations/dependencies/*,StackServices/config_types/*"
    query = (
        "?StackServices/service_name.in(HDFS,YARN,MAPREDUCE2,TEZ,HIVE,HBASE,SQOOP,ZOOKEEPER,"
        "AMBARI_INFRA_SOLR,AMBARI_METRICS,ATLAS,KAFKA,RANGER,SPARK3,ZEPPELIN,AIRFLOW,IMPALA,KUDU,OPENSEARCH,REDIS,HADOOP)"
        f"&fields={fields}"
    )
    data = get_api_data("stacks/ODP/versions/0.2/services", query)
    return jsonify(data)

@api_bp.route('/quicklink')
@auth_required
def get_quicklink():
    service_name = request.args.get('service')
    if not service_name:
        return make_response(jsonify({"message": "Missing 'service' query parameter"}), 400)    
    query_path = f"stacks/ODP/versions/0.2/services/{service_name}/quicklinks"
    query_params = "?QuickLinkInfo/default=true&fields=*"
    data = get_api_data(query_path, query_params)
    return jsonify(data)

@api_bp.route('/component-services')
@auth_required
def get_components():
    fields = (
        "ServiceComponentInfo/service_name,host_components/HostRoles/display_name,host_components/HostRoles/host_name,"
        "host_components/HostRoles/public_host_name,host_components/HostRoles/state,host_components/HostRoles/maintenance_state,"
        "host_components/HostRoles/stale_configs,host_components/HostRoles/ha_state,host_components/HostRoles/desired_admin_state,"
        "host_components/metrics/jvm/memHeapUsedM,host_components/metrics/jvm/HeapMemoryMax,host_components/metrics/jvm/HeapMemoryUsed,"
        "host_components/metrics/jvm/memHeapCommittedM,host_components/metrics/mapred/jobtracker/trackers_decommissioned,"
        "host_components/metrics/cpu/cpu_wio,host_components/metrics/rpc/client/RpcQueueTime_avg_time,"
        "host_components/metrics/dfs/FSNamesystem/*,host_components/metrics/dfs/namenode/Version,"
        "host_components/metrics/dfs/namenode/LiveNodes,host_components/metrics/dfs/namenode/DeadNodes,"
        "host_components/metrics/dfs/namenode/DecomNodes,host_components/metrics/dfs/namenode/TotalFiles,"
        "host_components/metrics/dfs/namenode/UpgradeFinalized,host_components/metrics/dfs/namenode/Safemode,"
        "host_components/metrics/runtime/StartTime,host_components/metrics/hbase/master/IsActiveMaster,"
        "host_components/metrics/hbase/master/MasterStartTime,host_components/metrics/hbase/master/MasterActiveTime,"
        "host_components/metrics/hbase/master/AverageLoad,host_components/metrics/master/AssignmentManager/ritCount,"
        "host_components/metrics/dfs/namenode/ClusterId&minimal_response=true"
    )
    query = f"?ServiceComponentInfo/category.in(MASTER,CLIENT)&fields={fields}"
    data = get_api_data("components", query)
    return jsonify(data)

@api_bp.route('/config-history')
@auth_required
def get_config_history():
    fields = (
        "service_config_version,user,group_id,group_name,is_current,createtime,service_name,"
        "hosts,service_config_version_note,is_cluster_compatible,stack_id&minimal_response=true"
    )
    query_path = (
        f"/configurations/service_config_versions?page_size=1000&from=0&sortBy=createtime.desc&fields={fields}"
    )
    data = get_api_data(query_path, "") 
    return jsonify(data)

@api_bp.route('/config')
@auth_required
def get_config():
    query_path = (
        "/configurations/service_config_versions?service_name.in(AMBARI_METRICS,HDFS,ZOOKEEPER,"
        "RANGER_KMS,RANGER,YARN,HIVE,KAFKA)&is_current=true"
    )
    data = get_api_data(query_path, "")
    return jsonify(data)

@api_bp.route('/heatmap-hbase')
@auth_required
def get_heatmap_hbase():
    try:
        type_param = request.args.get('selectedTime')
        if not type_param:
            return make_response(jsonify({"message": "Missing 'selectedTime' query parameter"}), 400)
        type_int = int(type_param)
    except ValueError:
        return make_response(jsonify({"message": "'selectedTime' must be an integer"}), 400)
    query_path = "services/HBASE/components/HBASE_REGIONSERVER"
    query_params = f"?fields=host_components/metrics/hbase/regionserver/{type_int}"
    data = get_api_data(query_path, query_params)
    return jsonify(data)