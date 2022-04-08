# NordVPN-NetworkManager-GUI a graphical frontend for both NordVPN and NetworkManager
# Copyright (C) 2018 Vincent Foster-Mueller

import configparser
import os
import json
import shutil
import subprocess
import sys
import time
from collections import namedtuple

import keyring
import prctl
import requests
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QAction, QMenu, QSystemTrayIcon, qApp

from .functions import *

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


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        """
        Initialize global variables and login UI, declare directories and paths
        """

        super(MainWindow, self).__init__()
        self.setObjectName("MainWindowObject")
        self.setWindowIcon(QtGui.QIcon(
            f"{os.path.dirname(__file__)}/assets/nordvpnicon.png")
        )
        self.base_dir = os.path.join(
            os.path.abspath(os.path.expanduser("~")), ".nordnmconfigs"
        )  # /home/username/.nordnmconfigs
        self.config_path = os.path.join(
            os.path.abspath(self.base_dir), ".configs"
        )
        self.scripts_path = os.path.join(
            os.path.abspath(self.base_dir), ".scripts"
        )
        self.network_manager_path = "/etc/NetworkManager/dispatcher.d/"
        self.conf_path = os.path.join(self.config_path, "nord_settings.conf")
        self.config = configparser.ConfigParser()

        with open("test/api_data.json", "r") as api_data:
            self.api_data = json.load(api_data)

        self.username = None
        self.password = None
        self.sudo_password = None
        self.connection_name = None
        self.connected_server = None
        self.domain_list = []
        self.server_info_list = []
        self.login_ui()
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(
            f"{os.path.dirname(__file__)}/assets/nordvpnicon.png"
        ))
        show_action = QAction("Show NordVPN Network Manager", self)
        quit_action = QAction("Exit", self)
        hide_action = QAction("Minimized", self)
        show_action.triggered.connect(self.show)
        hide_action.triggered.connect(self.hide)
        quit_action.triggered.connect(self.quitAppEvent)
        self.tray_icon.activated.connect(self.resume)
        tray_menu = QMenu()
        tray_menu.addAction(show_action)
        tray_menu.addAction(hide_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setToolTip("NordVPN")
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.show()

    def quitAppEvent(self):
        qApp.quit()

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def resume(self, activation_reason):
        if activation_reason == 3:
            self.show()

    def main_ui(self):
        """
        Display QT form for the main GUI interface.
        """
        font = QtGui.QFont()
        font.setPointSize(6)
        font.setStyleHint(QtGui.QFont.Monospace)

        self.resize(600, 650)
        size_policy_1 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred
        )
        size_policy_1.setHorizontalStretch(0)
        size_policy_1.setVerticalStretch(0)
        size_policy_1.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(size_policy_1)

        central_widget_ = QtWidgets.QWidget(self)
        central_widget_.setObjectName("central_widget_")
        self.title_label = QtWidgets.QLabel(central_widget_)
        size_policy_2 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred
        )
        size_policy_2.setHorizontalStretch(0)
        size_policy_2.setVerticalStretch(0)
        size_policy_2.setHeightForWidth(
            self.title_label.sizePolicy().hasHeightForWidth()
        )
        self.title_label.setSizePolicy(size_policy_2)
        self.title_label.setFont(font)
        self.title_label.setTextFormat(QtCore.Qt.RichText)
        self.title_label.setObjectName("title_label")

        grid_layout_1 = QtWidgets.QGridLayout(central_widget_)
        grid_layout_1.setObjectName("grid_layout_1")

        horizontal_layout_2 = QtWidgets.QHBoxLayout()
        horizontal_layout_2.setObjectName("horizontal_layout_2")
        spacer_item_1 = QtWidgets.QSpacerItem(
            40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum
        )
        horizontal_layout_2.addItem(spacer_item_1)

        horizontal_layout_2.addWidget(self.title_label)
        spacer_item_2 = QtWidgets.QSpacerItem(
            40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum
        )
        horizontal_layout_2.addItem(spacer_item_2)
        grid_layout_1.addLayout(horizontal_layout_2, 0, 0, 1, 2)

        vertical_layout_3 = QtWidgets.QVBoxLayout()
        vertical_layout_3.setObjectName("vertical_layout_3")
        self.country_list_label = QtWidgets.QLabel(central_widget_)
        self.country_list_label.setObjectName("country_list_label")
        vertical_layout_3.addWidget(self.country_list_label)

        line_1 = QtWidgets.QFrame(central_widget_)
        size_policy_3 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed
        )
        size_policy_3.setHorizontalStretch(0)
        size_policy_3.setVerticalStretch(0)
        size_policy_3.setHeightForWidth(
            line_1.sizePolicy().hasHeightForWidth()
        )
        line_1.setSizePolicy(size_policy_3)
        line_1.setMinimumSize(QtCore.QSize(180, 0))
        line_1.setFrameShape(QtWidgets.QFrame.HLine)
        line_1.setFrameShadow(QtWidgets.QFrame.Sunken)
        line_1.setObjectName("line")
        vertical_layout_3.addWidget(line_1)

        self.country_list = QtWidgets.QListWidget(central_widget_)
        self.country_list.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.country_list.setObjectName("country_list")
        vertical_layout_3.addWidget(self.country_list)

        grid_layout_1.addLayout(vertical_layout_3, 1, 0, 1, 1)
        horizontal_layout_1 = QtWidgets.QHBoxLayout()
        horizontal_layout_1.setObjectName("horizontal_layout_1")
        vertical_layout_1 = QtWidgets.QVBoxLayout()
        vertical_layout_1.setObjectName("vertical_layout_1")

        self.auto_connect_box = QtWidgets.QCheckBox(central_widget_)
        self.auto_connect_box.setObjectName("auto_connect_box")
        vertical_layout_1.addWidget(self.auto_connect_box)

        self.mac_changer_box = QtWidgets.QCheckBox(central_widget_)
        self.mac_changer_box.setObjectName("mac_changer_box")
        vertical_layout_1.addWidget(self.mac_changer_box)

        self.kill_switch_button = QtWidgets.QCheckBox(central_widget_)
        self.kill_switch_button.setObjectName("kill_switch_button")
        vertical_layout_1.addWidget(self.kill_switch_button)

        horizontal_layout_1.addLayout(vertical_layout_1)
        vertical_layout_2 = QtWidgets.QVBoxLayout()
        vertical_layout_2.setObjectName("vertical_layout_2")
        self.server_type_select = QtWidgets.QComboBox(central_widget_)
        size_policy_4 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Fixed
        )
        size_policy_4.setHorizontalStretch(0)
        size_policy_4.setVerticalStretch(0)
        size_policy_4.setHeightForWidth(
            self.server_type_select.sizePolicy().hasHeightForWidth()
        )
        self.server_type_select.setSizePolicy(size_policy_4)
        self.server_type_select.setObjectName("server_type_select")
        vertical_layout_2.addWidget(self.server_type_select)
        self.connection_type_select = QtWidgets.QComboBox(central_widget_)
        size_policy_5 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Fixed
        )
        size_policy_5.setHorizontalStretch(0)
        size_policy_5.setVerticalStretch(0)
        size_policy_5.setHeightForWidth(
            self.connection_type_select.sizePolicy().hasHeightForWidth()
        )
        self.connection_type_select.setSizePolicy(size_policy_5)
        self.connection_type_select.setObjectName("connection_type_select")
        vertical_layout_2.addWidget(self.connection_type_select)

        horizontal_layout_1.addLayout(vertical_layout_2)
        horizontal_layout_1.addItem(QtWidgets.QSpacerItem(
            40, 20, QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Minimum
        ))

        self.connect_button = QtWidgets.QPushButton(central_widget_)
        size_policy_6 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed
        )
        size_policy_6.setHorizontalStretch(0)
        size_policy_6.setVerticalStretch(0)
        size_policy_6.setHeightForWidth(
            self.connect_button.sizePolicy().hasHeightForWidth()
        )
        self.connect_button.setSizePolicy(size_policy_6)
        self.connect_button.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.connect_button.setObjectName("connect_button")
        horizontal_layout_1.addWidget(self.connect_button)

        self.disconnect_button = QtWidgets.QPushButton(central_widget_)
        self.disconnect_button.hide()
        size_policy_7 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed
        )
        size_policy_7.setHorizontalStretch(0)
        size_policy_7.setVerticalStretch(0)
        size_policy_7.setHeightForWidth(
            self.disconnect_button.sizePolicy().hasHeightForWidth()
        )
        self.disconnect_button.setSizePolicy(size_policy_7)
        self.disconnect_button.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.disconnect_button.setObjectName("disconnect_button")
        horizontal_layout_1.addWidget(self.disconnect_button)
        # BROKEN: one of these two calls to grid_layout_1.addLayout() is wrong
        grid_layout_1.addLayout(horizontal_layout_1, 2, 0, 1, 2)

        vertical_layout_4 = QtWidgets.QVBoxLayout()
        vertical_layout_4.setObjectName("vertical_layout_4")
        self.central_widget_label = QtWidgets.QLabel(central_widget_)
        self.central_widget_label.setObjectName("central_widget_label")
        vertical_layout_4.addWidget(self.central_widget_label)
        line_2 = QtWidgets.QFrame(central_widget_)
        size_policy_8 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed
        )
        size_policy_8.setHorizontalStretch(0)
        size_policy_8.setVerticalStretch(0)
        size_policy_8.setHeightForWidth(
            line_2.sizePolicy().hasHeightForWidth()
        )
        line_2.setSizePolicy(size_policy_8)
        line_2.setMinimumSize(QtCore.QSize(180, 0))
        line_2.setFrameShape(QtWidgets.QFrame.HLine)
        line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        line_2.setObjectName("line_2")
        vertical_layout_4.addWidget(line_2)
        self.server_list = QtWidgets.QListWidget(central_widget_)
        self.server_list.setObjectName("server_list")
        vertical_layout_4.addWidget(self.server_list)
        grid_layout_1.addLayout(vertical_layout_4, 1, 1, 1, 1)
        self.title_label.raise_()
        self.server_list.raise_()
        self.country_list.raise_()
        self.auto_connect_box.raise_()
        self.mac_changer_box.raise_()
        self.server_type_select.raise_()
        self.connection_type_select.raise_()
        self.country_list_label.raise_()
        self.central_widget_label.raise_()
        line_1.raise_()
        line_2.raise_()
        self.kill_switch_button.raise_()
        self.setCentralWidget(central_widget_)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        # # Begin of UI logic
        # try:
        #     resp = requests.get(api, timeout=5)
        #     if resp.status_code == requests.codes.ok:
        #         self.api_data = resp.json()
        #     else:
        #         print(resp.status_code, resp.reason)
        #         sys.exit(1)
        # except Exception as e:
        #     print(e)

        server_country_list = get_country_list(self.api_data)
        self.connection_type_select.addItems(connection_type_options)
        self.server_type_select.addItems(server_type_options)
        self.country_list.addItems(server_country_list)
        self.country_list.itemClicked.connect(self.get_server_list)
        self.server_type_select.currentTextChanged.connect(
            self.get_server_list
        )

        # Button functionality here
        self.connect_button.clicked.connect(self.connect)
        self.disconnect_button.clicked.connect(self.disconnect_vpn)
        self.auto_connect_box.clicked.connect(self.disable_auto_connect)
        self.kill_switch_button.clicked.connect(self.disable_kill_switch)

        self.parse_conf()
        self.repaint()
        self.get_active_vpn()
        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)
        QtWidgets.QApplication.processEvents()
        self.show()

    def login_ui(self):
        """
        Display login UI form.
        """

        self.resize(558, 468)
        size_policy_9 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred
        )
        size_policy_9.setHorizontalStretch(0)
        size_policy_9.setVerticalStretch(0)
        size_policy_9.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(size_policy_9)
        self.setWindowTitle("NordVPN login")
        central_widget_ = QtWidgets.QWidget(self)
        central_widget_.setObjectName("central_widget_")
        grid_layout_2 = QtWidgets.QGridLayout(central_widget_)
        grid_layout_2.setObjectName("grid_layout_2")

        vertical_layout_5 = QtWidgets.QVBoxLayout()
        vertical_layout_5.setObjectName("vertical_layout_5")
        self.nordImageWidget = QtWidgets.QLabel(central_widget_)
        self.nordImageWidget.setObjectName("nordImageWidget")
        vertical_layout_5.addWidget(self.nordImageWidget)

        vertical_layout_7 = QtWidgets.QVBoxLayout()
        vertical_layout_7.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint
        )
        vertical_layout_7.setContentsMargins(-1, 0, -1, -1)
        vertical_layout_7.setSpacing(6)
        vertical_layout_7.setObjectName("vertical_layout_7")
        horizontal_layout_4 = QtWidgets.QHBoxLayout()
        horizontal_layout_4.setObjectName("horizontal_layout_4")
        self.usernameLabel = QtWidgets.QLabel(central_widget_)
        self.usernameLabel.setObjectName("usernameLabel")
        horizontal_layout_4.addWidget(self.usernameLabel)
        self.user_input = QtWidgets.QLineEdit(central_widget_)
        size_policy_10 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding,
            QtWidgets.QSizePolicy.MinimumExpanding,
        )
        size_policy_10.setHorizontalStretch(0)
        size_policy_10.setVerticalStretch(0)
        size_policy_10.setHeightForWidth(
            self.user_input.sizePolicy().hasHeightForWidth()
        )
        self.user_input.setSizePolicy(size_policy_10)
        self.user_input.setMaximumSize(QtCore.QSize(200, 30))
        self.user_input.setBaseSize(QtCore.QSize(150, 50))
        self.user_input.setAlignment(QtCore.Qt.AlignCenter)
        self.user_input.setObjectName("user_input")
        horizontal_layout_4.addWidget(self.user_input)
        vertical_layout_7.addLayout(horizontal_layout_4)

        horizontal_layout_2 = QtWidgets.QHBoxLayout()
        horizontal_layout_2.setObjectName("horizontal_layout_2")
        self.passwordLabel = QtWidgets.QLabel(central_widget_)
        self.passwordLabel.setObjectName("passwordLabel")
        horizontal_layout_2.addWidget(self.passwordLabel)
        self.password_input = QtWidgets.QLineEdit(central_widget_)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        size_policy_11 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.MinimumExpanding,
            QtWidgets.QSizePolicy.MinimumExpanding,
        )
        size_policy_11.setHorizontalStretch(0)
        size_policy_11.setVerticalStretch(0)
        size_policy_11.setHeightForWidth(
            self.password_input.sizePolicy().hasHeightForWidth()
        )
        self.password_input.setSizePolicy(size_policy_11)
        self.password_input.setMaximumSize(QtCore.QSize(200, 30))
        self.password_input.setAlignment(QtCore.Qt.AlignCenter)
        self.password_input.setObjectName("password_input")
        horizontal_layout_2.addWidget(self.password_input)
        vertical_layout_7.addLayout(horizontal_layout_2)

        horizontal_layout_3 = QtWidgets.QHBoxLayout()
        horizontal_layout_3.setObjectName("horizontal_layout_3")
        horizontal_layout_3.addLayout(vertical_layout_7)
        horizontal_layout_3.addItem(QtWidgets.QSpacerItem(
            57, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum
        ))

        vertical_layout_6 = QtWidgets.QVBoxLayout()
        vertical_layout_6.setObjectName("vertical_layout_6")
        self.loginButton = QtWidgets.QPushButton(central_widget_)
        size_policy_12 = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed
        )
        size_policy_12.setHorizontalStretch(0)
        size_policy_12.setVerticalStretch(0)
        size_policy_12.setHeightForWidth(
            self.loginButton.sizePolicy().hasHeightForWidth()
        )
        self.loginButton.setSizePolicy(size_policy_12)
        self.loginButton.setObjectName("loginButton")
        vertical_layout_6.addWidget(self.loginButton)
        self.rememberCheckbox = QtWidgets.QCheckBox(central_widget_)
        self.rememberCheckbox.setObjectName("rememberCheckbox")
        vertical_layout_6.addWidget(self.rememberCheckbox)
        horizontal_layout_3.addLayout(vertical_layout_6)
        vertical_layout_5.addLayout(horizontal_layout_3)
        grid_layout_2.addLayout(vertical_layout_5, 0, 0, 1, 1)
        self.setCentralWidget(central_widget_)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        self.retranslate_login_ui()
        QtCore.QMetaObject.connectSlotsByName(self)

        self.check_config()  # does config exist else create

        # buttons here
        self.password_input.returnPressed.connect(self.loginButton.click)
        self.loginButton.clicked.connect(self.verify_credentials)

    def check_config(self):
        """
        Check if config directories and files exist and create them if they do
        not. If username is found in config, execute get_credentials()
        """

        try:
            if not os.path.isdir(self.base_dir):
                os.mkdir(self.base_dir)
            if not os.path.isdir(self.config_path):
                os.mkdir(self.config_path)
            if not os.path.isdir(self.scripts_path):
                os.mkdir(self.scripts_path)
            if not os.path.isfile(self.conf_path):
                self.config["USER"] = {"USER_NAME": "None"}
                self.config["SETTINGS"] = {
                    "MAC_RANDOMIZER": "false",
                    "KILL_SWITCH": "false",
                    "AUTO_CONNECT": "false",
                }
                write_conf(self.conf_path, self.config)

            self.config.read(self.conf_path)
            if (
                self.config.has_option("USER", "USER_NAME")
                and self.config.get("USER", "USER_NAME") != "None"
            ):
                self.statusbar.showMessage("Fetching Saved Credentials", 1000)
                self.username = self.config.get("USER", "USER_NAME")
                self.rememberCheckbox.setChecked(True)
                self.user_input.setText(self.username)
                self.get_credentials()

        except PermissionError:
            print("Insufficient permissions to create config folder")

    def get_credentials(self):
        try:
            keyring.get_keyring()
            password = keyring.get_password("NordVPN", self.username)
            self.password_input.setText(password)
        except Exception as e:
            print("Error fetching keyring")

    def parse_conf(self):
        """
        Parse config and manipulate UI to match.
        """

        self.config.read(self.conf_path)
        if self.config.getboolean("SETTINGS", "mac_randomizer"):
            self.mac_changer_box.setChecked(True)
        if self.config.getboolean("SETTINGS", "kill_switch"):
            self.kill_switch_button.setChecked(True)
        if self.config.getboolean("SETTINGS", "auto_connect"):
            self.auto_connect_box.setChecked(True)

    def verify_credentials(self):
        """
        Request a token from NordApi by sending the email and password in json
        format. Verify the response and update the GUI.
        """
        self.repaint()
        self.hide()
        self.main_ui()

    def get_server_list(self):
        """
        Display server information in the server_list based on the given filter
        (server_type, connection_type, current_country).
        """

        filtered = (
            self.country_list.currentItem().text(),
            self.server_type_select.currentText(),
            self.connection_type_select.currentText(),
        )
        server_name_list = []
        self.server_list.clear()
        self.domain_list.clear()
        self.server_info_list.clear()
        for server in self.api_data:
            categories, category_list = get_server_categories(
                server["categories"]
            )
            if server["name"] not in server_name_list and server["country"] == filtered[0] and filtered[1] in category_list:
                server_name_list.append(
                    f'{server["name"]}\n'
                    f'Load: {server["load"]}%\n'
                    f'Domain: {server["domain"]}\n'
                    f'Categories: {categories}'
                )
                self.domain_list.append(server["domain"])
                server = ServerInfo(
                    name=server["name"],
                    country=server["country"],
                    domain=server["domain"],
                    type=category_list,
                    load=server["load"],
                    categories=categories,
                )
                self.server_info_list.append(server)

        if server_name_list:
            # Sort lists to be in the same order
            server_name_list, self.domain_list, self.server_info_list = (
                list(x) for x in zip(*sorted(
                    zip(server_name_list, self.domain_list, self.server_info_list),
                    key=lambda x: x[2].load,
                ))
            )
            self.server_list.addItems(server_name_list)
        else:
            self.server_list.addItem("No Servers Found")

        QtWidgets.QApplication.processEvents()
        self.retranslateUi()

    def get_ovpn(self):
        """
        Get OVPN file from nord servers and save it to a temporary location.
        e.g. https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/sg173.nordvpn.com.udp.ovpn
        """

        configs_path = "https://downloads.nordcdn.com/configs/files"
        obs = "ovpn_xor" if self.server_type_select.currentText(
        ) == "Obfuscated Server" else "ovpn"
        prot = "tcp" if self.connection_type_select.currentText() == "TCP" else "udp"
        ovpn_url = f"{configs_path}/{obs}_{prot}/servers/"

        current_server = self.domain_list[self.server_list.currentRow()]
        filename = f'{current_server}.{prot}.ovpn'

        ovpn_file = requests.get(ovpn_url + filename, stream=True)
        if ovpn_file.status_code == requests.codes.ok:
            self.ovpn_path = os.path.join(self.config_path, filename)
            with open(self.ovpn_path, "wb") as out_file:
                shutil.copyfileobj(ovpn_file.raw, out_file)
        else:
            print("Error fetching configuration files")

        self.server_list.setFocus()

    def import_ovpn(self):
        """
        Rename and import OVPN file to NetworkManager and clean up temp files.
        """

        try:
            self.statusbar.showMessage("Importing connection...")
            self.repaint()
            self.connection_name = self.generate_connection_name()
            ovpn_file = f'{self.connection_name}.ovpn'

            # Change name from default
            path = os.path.join(self.config_path, ovpn_file)
            shutil.copy(self.ovpn_path, path)
            os.remove(self.ovpn_path)
            output = subprocess.run([
                "nmcli", "connection", "import", "type", "openvpn", "file", path
            ])
            output.check_returncode()
            os.remove(path)

        except subprocess.CalledProcessError:
            print("ERROR: Importing VPN configuration")

    def generate_connection_name(self):
        """
        Generate the name of the OVPN file.
        """

        server = self.server_info_list[self.server_list.currentRow()]
        category_name = ""
        for i, category in enumerate(server.type):
            if i > 0:
                category_name += f' | {category}'
            else:
                category_name = category

        return (
            f"{server.name} [{category_name}] [{self.connection_type_select.currentText()}]"
        )

    def get_active_vpn(self):
        """
        Query NetworkManager for the current connection.
        If a current connection is found, set the UI to the appropriate state.

        :return Bool
        """

        try:
            output = subprocess.run([
                "nmcli",
                "--mode", "tabular",
                "--terse",
                "--fields", "TYPE,NAME",
                "connection", "show", "--active",
            ], stdout=subprocess.PIPE)
            output.check_returncode()
            for line in output.stdout.decode("utf-8").strip().split("\n"):
                try:
                    elements = line.strip().split(":")
                    if elements[0] == "vpn":
                        connection_name = elements[1]
                        connection_info = connection_name.split()
                        country = connection_info[0]
                        server_name, server_type = get_connection_info(
                            connection_info
                        )
                        if self.server_info_list:  # vpn connected successfully
                            for server in self.server_info_list:
                                if server_name == server.name:
                                    self.connected_server = server.name
                                    return True
                        else:
                            self.connect_button.hide()
                            self.disconnect_button.show()
                            print("Fetching active server...")
                            self.repaint()
                            item = self.country_list.findItems(
                                country, QtCore.Qt.MatchExactly
                            )
                            self.country_list.setCurrentItem(item[0])
                            self.server_type_select.setCurrentIndex(
                                server_type
                            )
                            self.get_server_list()
                            for server in self.server_info_list:
                                if server_name == server.name:
                                    server_list_item = self.server_list.findItems(
                                        f"{server_name}\nLoad: {server.load}%\nDomain: {server.domain}\nCategories: {server.categories}",
                                        QtCore.Qt.MatchExactly,
                                    )
                                    self.server_list.setCurrentItem(
                                        server_list_item[0]
                                    )
                                    self.server_list.setFocus()
                                    self.connection_name = connection_name
                                    self.connected_server = server.name
                                    return False
                except Exception as e:
                    print(e)

        except subprocess.CalledProcessError:
            print("ERROR: Network Manager query error")
            self.repaint()

    def randomize_mac(self):
        """
        Take down network interface and bring it back with a new MAC address.
        """

        try:
            self.statusbar.showMessage("Randomizing MAC Address", 2000)
            self.repaint()
            output = subprocess.run([
                "nmcli",
                "--mode", "tabular",
                "--terse", "--fields", "TYPE,UUID",
                "connection", "show", "--active",
            ], stdout=subprocess.PIPE)
            output.check_returncode()
            lines = output.stdout.decode("utf-8").split("\n")

            for line in lines:
                elements = line.strip().split(":")
                uuid = elements[1]
                connection_type = elements[0]
                if type != "vpn":
                    subprocess.run(["nmcli", "connection", "down", uuid])
                    subprocess.run([
                        "nmcli", "connection", "modify", "--temporary",
                        uuid,
                        f'{connection_type}.cloned-mac-address',
                        "random",
                    ])
                    subprocess.run(["nmcli", "connection", "up", uuid])

            print("Random MAC Address assigned", 2000)
            write_conf(self.conf_path, self.config)
            self.repaint()
        except subprocess.CalledProcessError:
            print("ERROR: Randomizer failed", 2000)
            self.repaint()

    def get_sudo(self):
        """
        Sudo dialog UI form
        TODO: Remove in favour of a DBUS based approach
        """

        sudo = QtWidgets.QDialog(self)
        sudo.setModal(True)
        sudo.resize(399, 206)
        icon = QtGui.QIcon.fromTheme("changes-prevent")
        sudo.setWindowIcon(icon)
        sudo.sudo_grid_layout = QtWidgets.QGridLayout(sudo)
        sudo.sudo_grid_layout.setObjectName("sudo_grid_layout")
        sudo.sudo_vertical_layout = QtWidgets.QVBoxLayout()
        sudo.sudo_vertical_layout.setContentsMargins(-1, 18, -1, -1)
        sudo.sudo_vertical_layout.setSpacing(16)
        sudo.sudo_vertical_layout.setObjectName("sudo_vertical_layout")
        sudo.sudo_text_label = QtWidgets.QLabel(sudo)
        sudo.sudo_text_label.setTextFormat(QtCore.Qt.RichText)
        sudo.sudo_text_label.setAlignment(
            QtCore.Qt.AlignLeading | QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter
        )
        sudo.sudo_text_label.setWordWrap(True)
        sudo.sudo_text_label.setObjectName("sudo_text_label")
        sudo.sudo_vertical_layout.addWidget(sudo.sudo_text_label)
        sudo.sudo_password = QtWidgets.QLineEdit(self)
        sudo.sudo_password.setCursor(QtGui.QCursor(QtCore.Qt.IBeamCursor))
        sudo.sudo_password.setAlignment(QtCore.Qt.AlignCenter)
        sudo.sudo_password.setClearButtonEnabled(False)
        sudo.sudo_password.setObjectName("sudo_password")
        sudo.sudo_password.setEchoMode(QtWidgets.QLineEdit.Password)
        sudo.sudo_vertical_layout.addWidget(sudo.sudo_password)
        sudo.sudo_grid_layout.addLayout(sudo.sudo_vertical_layout, 0, 0, 1, 1)
        sudo.sudo_layout = QtWidgets.QHBoxLayout()
        sudo.sudo_layout.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint)
        sudo.sudo_layout.setContentsMargins(-1, 0, -1, 6)
        sudo.sudo_layout.setSpacing(0)
        sudo.sudo_layout.setObjectName("sudo_layout")
        sudo.sudo_layout.addItem(QtWidgets.QSpacerItem(
            178, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum
        ))
        sudo.sudo_accept_box = QtWidgets.QDialogButtonBox(sudo)
        sudo.sudo_accept_box.setOrientation(QtCore.Qt.Horizontal)
        sudo.sudo_accept_box.addButton(
            "Login", QtWidgets.QDialogButtonBox.AcceptRole
        )
        sudo.sudo_accept_box.addButton(
            "Cancel", QtWidgets.QDialogButtonBox.RejectRole
        )
        sudo.sudo_accept_box.setObjectName("sudo_accept_box")
        sudo.sudo_layout.addWidget(sudo.sudo_accept_box)
        sudo.sudo_grid_layout.addLayout(sudo.sudo_layout, 1, 0, 1, 1)
        sudo.setWindowTitle("Authentication needed")
        sudo.sudo_text_label.setText(
            '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated privileges.</p></body></html>'
        )
        # button functionality here
        sudo.sudo_accept_box.accepted.connect(self.check_sudo)
        sudo.sudo_accept_box.rejected.connect(self.close_sudo)
        QtCore.QMetaObject.connectSlotsByName(sudo)
        return sudo

    def close_sudo(self):
        # Clear sudo password when cancel is pressed.

        self.sudo_password = None
        self.sudo.close()

    def check_sudo(self):
        """
        Check validity of sudo password.
        :return: True if valid False if invalid
        """

        self.sudo_password = self.sudo.sudo_password.text()
        try:
            p1 = echo_sudo(self.sudo_password)
            p2 = subprocess.Popen(
                ["sudo", "-S", "whoami"],
                encoding="utf-8",
                stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            p1.stdout.close()
            output = p2.communicate()[0].strip()
            p2.stdout.close()

            if "root" in output:
                self.sudo.close()
                return True
            else:
                error = QtWidgets.QErrorMessage(self.sudo)
                error.showMessage("Invalid Password")
                return False
        except Exception as e:
            print("failed", e)
            self.sudo_password = None

    def set_auto_connect(self):
        """
        Generate auto_connect bash script and move it to NetworkManager.
        """

        self.config.read(self.conf_path)
        if interfaces := get_interfaces():
            interface_string = "|".join(interfaces)
            script = f"""
            #!/bin/bash
            if [[ "$1" =~ '{interface_string}' ]] && [[ "$2" =~ up|connectivity-change ]]
            then
                nmcli con up id "' + self.generate_connection_name() + '"
            fi
            """
        try:
            with open(
                os.path.join(self.scripts_path, "auto_connect"), "w"
            ) as auto_connect:
                print(script, file=auto_connect)
        except Exception as e:
            print(e)
            print("ERROR building script file")
        try:
            p1 = echo_sudo(self.sudo_password)
            p2 = subprocess.Popen([
                "sudo", "-S", "mv",
                f'{self.scripts_path}/auto_connect',
                f'{self.network_manager_path}auto_connect',
            ], stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()
            p2.stdout.close()
            p3 = echo_sudo(self.sudo_password)
            p4 = subprocess.Popen([
                "sudo", "-S", "chown", "root:root",
                f'{self.network_manager_path}auto_connect',
            ], stdin=p3.stdout, stdout=subprocess.PIPE,)
            p3.stdout.close()
            p4.stdout.close()
            p5 = echo_sudo(self.sudo_password)
            p6 = subprocess.Popen([
                "sudo", "-S", "chmod", "744",
                f'{self.network_manager_path}auto_connect',
            ], stdin=p5.stdout, stdout=subprocess.PIPE,)
            p5.stdout.close()
            p6.stdout.close()
            self.config["SETTINGS"]["auto_connect"] = True
            write_conf(self.conf_path, self.config)
        except Exception as e:
            print(e)

    def disable_auto_connect(self):
        """
        Handle enabling and disabling of auto-connect depending on UI state.
        Called everytime the auto-connect box is clicked.
        """

        self.config.read(self.conf_path)

        if not self.auto_connect_box.isChecked() and not self.sudo_password and self.config.getboolean("SETTINGS", "auto_connect"):
            self.sudo = self.get_sudo()
            self.sudo.exec_()
            if not self.sudo_password:  # dialog was canceled
                return False
            try:
                p1 = echo_sudo(self.sudo_password)
                p2 = subprocess.Popen([
                    "sudo", "-S", "rm",
                    f'{self.network_manager_path}auto_connect'
                ], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                p1.stdout.close()
                p2.stdout.close()
                self.config["SETTINGS"]["auto_connect"] = False
                write_conf(self.conf_path, self.config)
            except Exception as e:
                print(e)

        elif not self.auto_connect_box.isChecked() and self.sudo_password and self.config.getboolean("SETTINGS", "auto_connect"):
            try:
                p1 = echo_sudo(self.sudo_password)
                p2 = subprocess.Popen([
                    "sudo", "-S", "rm",
                    f'{self.network_manager_path}auto_connect',
                ], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p1.stdout.close()
                p2.stdout.close()
                self.config["SETTINGS"]["auto_connect"] = False
                write_conf(self.conf_path, self.config)
            except Exception as e:
                print(e)
        elif self.auto_connect_box.isChecked() and self.get_active_vpn() and self.sudo_password:
            self.set_auto_connect()

        elif self.auto_connect_box.isChecked() and self.get_active_vpn() and not self.sudo_password:
            self.sudo = self.get_sudo()
            self.sudo.exec_()
            if self.sudo_password:
                self.set_auto_connect()
            else:
                self.auto_connect_box.setChecked(False)
                return False

    def set_kill_switch(self):
        """
        Generate bash kill switch script and move it to NetworkManager.
        """

        script = f"""
        #!/bin/bash
        PERSISTENCE_FILE={os.path.join(self.scripts_path, ".killswitch_data")}
        case $2 in
            vpn-up)
            nmcli -f type,device connection | awk '$1~/^vpn$/ && $2~/[^\-][^\-]/ {{ print $2; }}' > "${{PERSISTENCE_FILE}}"
            ;;
            vpn-down)
            xargs -n 1 -a "${{PERSISTENCE_FILE}}" nmcli device disconnect
            ;;
        esac
        """

        try:
            with open(
                os.path.join(self.scripts_path, "kill_switch"), "w"
            ) as kill_switch:
                print(script, file=kill_switch)

            p1 = echo_sudo(self.sudo_password)
            p2 = subprocess.Popen([
                "sudo", "-S", "mv",
                f'{self.scripts_path}/kill_switch',
                f'{self.network_manager_path}kill_switch',
            ], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p1.stdout.close()
            p2.stdout.close()
            time.sleep(0.5)
            p3 = echo_sudo(self.sudo_password)
            p4 = subprocess.Popen([
                "sudo", "-S", "chown", "root:root", f'{self.network_manager_path}kill_switch',
            ], stdin=p3.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            time.sleep(0.5)
            p3.stdout.close()
            p4.stdout.close()
            p5 = echo_sudo(self.sudo_password)
            p6 = subprocess.Popen([
                "sudo", "-S", "chmod", "744", f'{self.network_manager_path}kill_switch',
            ], stdin=p5.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p5.stdout.close()
            p6.stdout.close()
            self.config["SETTINGS"]["kill_switch"] = True
            write_conf(self.conf_path, self.config)
            self.statusbar.showMessage("Kill switch activated", 2000)
            self.repaint()
        except Exception as e:
            print(e)

    def disable_kill_switch(self):
        """
        Enable or disable the kill switch depending on UI state. Called every
        time the kill switch button is pressed.
        """
        if not self.kill_switch_button.isChecked() and not self.sudo_password and self.config.getboolean("SETTINGS", "kill_switch"):
            self.sudo = self.get_sudo()
            self.sudo.exec_()

            if not self.sudo_password:  # dialog was canceled
                self.kill_switch_button.setChecked(False)
                return False
            try:
                p1 = echo_sudo(self.sudo_password)
                p2 = subprocess.Popen([
                    "sudo", "-S", "rm", f'{self.network_manager_path}kill_switch',
                ], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

                p1.stdout.close()
                p2.stdout.close()
                self.statusbar.showMessage("Kill switch disabled", 2000)
                self.repaint()
                self.config["SETTINGS"]["kill_switch"] = False
                write_conf(self.conf_path, self.config)

            except subprocess.CalledProcessError:
                print("ERROR disabling kill switch", 2000)
                self.repaint()

        elif (
            not self.kill_switch_button.isChecked()
            and self.sudo_password
            and self.config.getboolean("SETTINGS", "kill_switch")
        ):

            try:
                p1 = echo_sudo(self.sudo_password)
                p2 = subprocess.Popen([
                    "sudo", "-S", "rm",
                    f'{self.network_manager_path}kill_switch',
                ], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p1.stdout.close()
                p2.stdout.close()
                self.statusbar.showMessage("Kill switch disabled", 2000)
                self.repaint()
                self.config["SETTINGS"]["kill_switch"] = False
                write_conf(self.conf_path, self.config)

            except subprocess.CalledProcessError:
                print("ERROR disabling kill switch")
                self.repaint()

        elif self.kill_switch_button.isChecked() and self.get_active_vpn() and self.sudo_password:
            self.set_kill_switch()

        elif self.kill_switch_button.isChecked() and self.get_active_vpn() and not self.sudo_password:
            self.sudo = self.get_sudo()
            self.sudo.exec_()
            if self.sudo_password:
                self.set_kill_switch()
            else:
                self.kill_switch_button.setChecked(False)
                return False

    def disable_ipv6(self):
        if not self.sudo_password:
            self.sudo = self.get_sudo()
            self.sudo.exec_()

        try:
            p1 = echo_sudo(self.sudo_password)
            p2 = subprocess.Popen([
                "sudo", "-S", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1",
                "&&",
                "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0",
            ], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p1.stdout.close()
            p2.stdout.close()
        except subprocess.CalledProcessError:
            print("ERROR: disabling IPV6 failed")

    def enable_ipv6(self):
        if not self.sudo_password:
            self.sudo = self.get_sudo()
            self.sudo.exec_()

        try:
            p1 = echo_sudo(self.sudo_password)
            p2 = subprocess.Popen([
                "sudo", "-S", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0",
                "&&",
                "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0",
            ], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p1.stdout.close()
            p2.stdout.close()
        except subprocess.CalledProcessError:
            print("ERROR: Enabling IPV6 failed", 2000)

    def connect(self):
        """
        Step through all of the UI Logic for connecting to the VPN.
        """

        if self.mac_changer_box.isChecked():
            self.randomize_mac()
            self.config["SETTINGS"]["mac_randomizer"] = "true"
        else:
            self.config["SETTINGS"]["mac_randomizer"] = "false"
        write_conf(self.conf_path, self.config)
        if self.auto_connect_box.isChecked():
            if not self.sudo_password:  # prompt for sudo password
                self.sudo = self.get_sudo()
                self.sudo.exec_()

                if self.sudo_password:  # valid password exists
                    self.set_auto_connect()
                else:
                    self.auto_connect_box.setChecked(False)
                    return False
            else:
                self.set_auto_connect()
        if self.server_type_select.currentText() == "Double VPN":
            # set to TCP; perhaps add pop up to give user the choice?
            self.connection_type_select.setCurrentIndex(1)
        self.disable_ipv6()
        self.get_ovpn()
        self.import_ovpn()
        add_secrets(self.connection_name, self.username, self.password)
        enable_connection(self.connection_name)
        self.statusbar.clearMessage()
        self.repaint()

        if self.kill_switch_button.isChecked():
            if not self.sudo_password:
                self.sudo = self.get_sudo()
                self.sudo.exec_()
            if not self.sudo_password:  # dialog was closed
                self.kill_switch_button.setChecked(False)
                return False
            self.set_kill_switch()

        # UI changes here
        if self.get_active_vpn():  # if connection successful
            self.connect_button.hide()
            self.disconnect_button.show()
            self.retranslateUi()

    def disconnect_vpn(self):
        """
        Step through all of the UI logic to disconnect the VPN.
        """

        if self.kill_switch_button.isChecked():
            self.kill_switch_button.setChecked(False)
            self.statusbar.showMessage("Disabling Killswitch...", 5000)
            self.repaint()
            self.disable_kill_switch()
            time.sleep(5)  # sleep while NetworkManager is killing connection

        if self.auto_connect_box.isChecked():
            self.auto_connect_box.setChecked(False)
            self.statusbar.showMessage("Disabling auto-connect...", 1000)
            self.disable_auto_connect()
        if self.connection_name is None:
            print("no connection")
        else:
            disable_connection(self.connection_name)
            remove_connection(self.connection_name)
        self.enable_ipv6()
        self.statusbar.clearMessage()
        self.repaint()

        # UI changes here
        self.disconnect_button.hide()
        self.connect_button.show()
        self.retranslateUi()

    def retranslateUi(self):
        _tr = QtCore.QCoreApplication.translate
        # self.setWindowTitle(_tr("MainWindow", " "))
        self.title_label.setText(_tr(
            "MainWindow",
            f'<html><head/><body><p align="center"><img src="{os.path.dirname(__file__)}/assets/nord-logo.png"/></p></body></html>',
        ))
        self.country_list_label.setText(_tr("MainWindow", "Countries"))
        self.auto_connect_box.setStatusTip(_tr(
            "MainWindow", "Network Manager will auto-connect on system start"
        ))
        self.auto_connect_box.setText(_tr("MainWindow", "Auto connect"))
        self.mac_changer_box.setStatusTip(_tr(
            "MainWindow", "Randomize MAC address"
        ))
        self.mac_changer_box.setText(_tr("MainWindow", "Randomize MAC"))
        self.kill_switch_button.setStatusTip(_tr(
            "MainWindow", "Disables internet connection if VPN connectivity is lost"
        ))
        self.kill_switch_button.setText(_tr("MainWindow", "Kill Switch"))
        self.server_type_select.setStatusTip(_tr(
            "MainWindow", "Select Server Type"
        ))
        self.connection_type_select.setStatusTip(_tr(
            "MainWindow", "Select connection type"
        ))
        self.connect_button.setText(_tr("MainWindow", "Connect"))
        self.disconnect_button.setText(_tr("MainWindow", "Disconnect"))
        self.central_widget_label.setText(_tr("MainWindow", "Servers"))

    def retranslate_login_ui(self):
        _tr = QtCore.QCoreApplication.translate
        self.nordImageWidget.setText(_tr(
            "MainWindow",
            f'<html><head/><body><p align="center"><img src="{os.path.dirname(__file__)}/assets/nordvpnicon.png"/></p><p align="center"><br/></p></body></html>',
        ))
        self.usernameLabel.setText(_tr(
            "MainWindow",
            '<html><head/><body><p align="right">Email:     </p></body></html>',
        ))
        self.passwordLabel.setText(_tr(
            "MainWindow",
            '<html><head/><body><p align="right">Password:     </p></body></html>',
        ))
        self.loginButton.setText(_tr("MainWindow", "Login"))
        self.rememberCheckbox.setText(_tr("MainWindow", "Remember"))


def main():
    app_name = "NordVPN"
    prctl.set_name(app_name)
    prctl.set_proctitle(app_name)
    app = QtWidgets.QApplication(sys.argv)
    MainWindow()
    sys.exit(app.exec_())
