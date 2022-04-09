import subprocess
import keyring
import os


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


def country_spaces(connection_info):
    """
    Take everything before the first element containing a hash (the endpoint
    number) and stuff it into element 0, popping other elements, in order to
    handle country names containing spaces.
    """

    endpoint_number = [i for i, x in enumerate(connection_info) if '#' in x][0]
    connection_info[0] = ' '.join(connection_info[:endpoint_number])
    for _element in range(endpoint_number-1):
        connection_info.pop(1)
    return connection_info


def get_connection_info(connection_info):
    """
    Return a standardised name and type for the provided connection.
    """

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
        lines = output.stdout.decode("utf-8").split("\n")
        interfaces = []
        for line in lines:
            if line:
                elements = line.strip().split(":")
                if elements[0] in ["wifi", "ethernet"]:
                    interfaces.append(elements[1])
        return interfaces

    except Exception as e:
        print(e)


def remove_connection(connection_name, sudo_password):
    try:
        subprocess.run(
            ["nmcli", "connection", "delete", connection_name],
            stdin=echo_sudo(sudo_password).stdout
        )
    except Exception as e:
        print(e)


def disable_connection(connection_name, sudo_password):
    try:
        subprocess.run(
            ["nmcli", "connection", "down", connection_name],
            stdin=echo_sudo(sudo_password).stdout
        )
    except Exception as e:
        print(e)


def enable_connection(connection_name, sudo_password):
    try:
        subprocess.run(
            ["nmcli", "connection", "up", connection_name],
            stdin=echo_sudo(sudo_password).stdout
        )
    except Exception as e:
        print(e)


def nm_mod(connection_name, config_option, config_value, sudo_password):
    try:
        return subprocess.run(
            [
                "nmcli", "connection", "modify",
                connection_name, config_option, config_value,
            ],
            stdin=echo_sudo(sudo_password).stdout
        )
    except Exception as e:
        print(e)


def echo_sudo(sudo_password):
    return subprocess.Popen(
        ["echo", sudo_password],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def write_conf(conf_path, config):
    with open(conf_path, "w") as configfile:
        config.write(configfile)

    configfile.close()


def add_secrets(connection_name, username, password, sudo_password):
    """
    Add the username and password to the NetworkManager configuration.
    """

    nm_mod(connection_name, "+vpn.data", "password-flags=0", sudo_password)
    nm_mod(
        connection_name, "+vpn.secrets", f'password={password}', sudo_password
    )
    nm_mod(connection_name, "+vpn.data", f'username={username}', sudo_password)
    nm_mod(connection_name, "+ipv6.method", "ignore", sudo_password)
    nm_mod(connection_name, "+vpn.data", "password-flags=0", sudo_password)


def check_config(base_dir, config_path, scripts_path, conf_path, config):
    """
    Check if config directories and files exist and create them if they do
    not. If username is found in config, fetch password from keyring
    """

    username = None
    password = None

    try:
        if not os.path.isdir(base_dir):
            os.mkdir(base_dir)
        if not os.path.isdir(config_path):
            os.mkdir(config_path)
        if not os.path.isdir(scripts_path):
            os.mkdir(scripts_path)
        if not os.path.isfile(conf_path):
            config["USER"] = {"USER_NAME": "None"}
            config["SETTINGS"] = {
                "MAC_RANDOMIZER": "false",
                "KILL_SWITCH": "false",
                "AUTO_CONNECT": "false",
            }
            print("No config file found, writing defaults")
            write_conf(conf_path, config)

        config.read(conf_path)
        if (
            config.has_option("USER", "USER_NAME")
            and config.get("USER", "USER_NAME") != "None"
        ):
            print("User found in config, retrieving password from keyring")
            username = config.get("USER", "USER_NAME")
            try:
                keyring.get_keyring()
                password = keyring.get_password("NordVPN", username)
            except Exception as e:
                print("Error fetching keyring")
        return username, password

    except Exception as e:
        print(e)
