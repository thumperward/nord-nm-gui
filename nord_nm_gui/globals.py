import os
from collections import namedtuple

connection_type_options = ["UDP", "TCP"]
server_type_options = [
    "P2P",
    "Standard",
    "Double VPN",
    "TOR over VPN",
    "Dedicated IP",
]  # , 'Anti-DDoS', 'Obfuscated Server']
api = "https://api.nordvpn.com/server"
ServerInfo = namedtuple(
    "ServerInfo", "name, country, domain, type, load, categories"
)
base_dir = os.path.join(
    os.path.abspath(os.path.expanduser("~")), ".nordnmconfigs"
)
config_path = os.path.join(os.path.abspath(base_dir), ".configs")
scripts_path = os.path.join(os.path.abspath(base_dir), ".scripts")
network_manager_path = "/etc/NetworkManager/dispatcher.d/"
conf_path = os.path.join(config_path, "nord_settings.conf")
