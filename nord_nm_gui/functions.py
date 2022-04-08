import subprocess


def get_country_list(api_data):
    """
    Parse JSON file for countries with servers available and display them
    in the server_country_list box of the UI.

    :param api_data: server information in json format
    :return: list of countries sorted alphabetically
    """
    server_country_list = []
    for server in api_data:
        country = server["country"]
        if country not in server_country_list:
            server_country_list.append(country)
    return sorted(server_country_list)


def get_server_categories(categories):
    category_string = ""
    category_list = []
    for category in categories:
        if category["name"] == "Standard VPN servers":
            category_string += "Standard "
            category_list.append("Standard")
        elif category["name"] == "P2P":
            category_string += f'{category["name"]} '
            category_list.append("P2P")
        elif category["name"] == "Anti-DDoS":
            category_string += f'{category["name"]} '
            category_list.append("Anti-DDoS")
        elif category["name"] == "Obfuscated Servers":
            category_string += "Obfuscated"
            category_list.append("Obfuscated Server")
        elif category["name"] == "Dedicated IP":
            category_string += f'{category["name"]} '
            category_list.append("Dedicated IP")
        elif category["name"] == "Double VPN":
            category_string += f'{category["name"]} '
            category_list.append("Double VPN")
        elif category["name"] == "Onion Over VPN":
            category_string += f'{category["name"]} '
            category_list.append("TOR over VPN")
        else:
            category_string += f'{category["name"]} '
    return category_string, category_list


def get_connection_info(connection_info):
    server_name = ''
    server_type = 0
    if (
        "[Standard" in connection_info or "[Standard]" in connection_info
        or (
            "[Double" not in connection_info
            and "[TOR" not in connection_info
            and "[Dedicated" in connection_info
        )
    ):
        # Normal servers
        server_name = f"{connection_info[0]} {connection_info[1]}"
    elif "[Double" in connection_info:
        # Double VPN server
        server_name = f'{connection_info[0]} - {connection_info[2]} {connection_info[3]}'
    elif "[TOR" in connection_info:
        # Onion Over VPN
        server_name = f'{connection_info[0]} {connection_info[1]} {connection_info[2]}'

    if "[Standard" in connection_info or "[Standard]" in connection_info:
        server_type = 1
    elif "[Double" in connection_info:
        server_type = 2
    elif "[TOR" in connection_info:
        server_type = 3
    elif "[Dedicated" in connection_info:
        server_type = 4
    elif "[TCP]" in connection_info:
        server_type = 1
    return server_name, server_type


def get_interfaces():
    """
    Get current network interfaces.

    :return: List of network interfaces
    """

    try:
        output = subprocess.run([
            "nmcli",
            "--mode", "tabular",
            "--terse", "--fields", "TYPE,DEVICE", "device", "status",
        ], stdout=subprocess.PIPE)
        output.check_returncode()
        lines = output.stdout.decode("utf-8").split("\n")
        interfaces = []

        for line in lines:
            if line:
                elements = line.strip().split(":")

                if elements[0] in ["wifi", "ethernet"]:
                    interfaces.append(elements[1])

        return interfaces

    except subprocess.CalledProcessError:
        print("ERROR Fetching interfaces")


def remove_connection(connection_name):
    try:
        connection = subprocess.run([
            "nmcli", "connection", "delete", connection_name
        ])
        connection.check_returncode()
    except subprocess.CalledProcessError:
        print("ERROR: Failed to remove Connection")


def disable_connection(connection_name):
    try:
        connection = subprocess.run(
            ["nmcli", "connection", "down", connection_name]
        )
        connection.check_returncode()
    except subprocess.CalledProcessError:
        print("ERROR: Disconnection Failed", 2000)


def enable_connection(connection_name):
    try:
        connection = subprocess.run([
            "nmcli", "connection", "up", connection_name
        ])
        connection.check_returncode()
    except subprocess.CalledProcessError:
        print("ERROR: Connection Failed", 2000)


def nm_mod(connection_name, config_option, config_value):
    try:
        process = subprocess.run([
            "nmcli", "connection", "modify",
            connection_name, config_option, config_value,
        ])
        process.check_returncode()
        return process
    except subprocess.CalledProcessError:
        print("ERROR: nmcli command failed", 2000)


def echo_sudo(sudo_password):
    return subprocess.Popen(
        ["echo", sudo_password],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def write_conf(conf_path, config):
    with open(conf_path, "w") as configfile:
        config.write(configfile)

    configfile.close()


def add_secrets(connection_name, username, password):
    """
    Add the username and password to the NetworkManager configuration.
    """

    nm_mod(connection_name, "+vpn.data", "password-flags=0")
    nm_mod(
        connection_name, "+vpn.secrets", f'password={password}'
    )
    nm_mod(connection_name, "+vpn.data", f'username={username}')
    nm_mod(connection_name, "+ipv6.method", "ignore")
    nm_mod(connection_name, "+vpn.data", "password-flags=0")
