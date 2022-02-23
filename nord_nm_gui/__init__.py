# NordVPN-NetworkManager-GUI a graphical frontend for both NordVPN and NetworkManager
# Copyright (C) 2018 Vincent Foster-Mueller

import configparser
import os
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
        # the following tries to print a status bar message if it fails, but
        # the UI has not yet been initialised
        self.username = None
        self.password = None
        self.sudo_password = None
        self.connection_name = None
        self.connected_server = None
        self.domain_list = []
        self.server_info_list = []
        self.login_ui()

        """
        Initialize system tray icon.
        """

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

        """
        Initialize GUI.
        """

        self.show()

    def quitAppEvent(self):
        """
        Quit GUI from system tray.
        """

        qApp.quit()

    def closeEvent(self, event):
        """
        Override default close event.
        """

        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "NordVPN Network Manager",
            "NordVPN Network Manager was minimized to System Tray",
            QSystemTrayIcon.Information,
            2500,
        )

    def resume(self, activation_reason):
        """
        Resume from system tray.
        """

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
        spacer_item_3 = QtWidgets.QSpacerItem(
            40,
            20,
            QtWidgets.QSizePolicy.MinimumExpanding,
            QtWidgets.QSizePolicy.Minimum,
        )
        horizontal_layout_1.addItem(spacer_item_3)

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

        grid_layout_1.addLayout(horizontal_layout_1, 2, 0, 1, 2)

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

        # BROKEN: already added to grid_layout_1 above
        # grid_layout_1.addLayout(horizontal_layout_1, 2, 0, 1, 2)

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

        # Begin of UI logic

        try:
            resp = requests.get(api, timeout=5)
            if resp.status_code == requests.codes.ok:
                self.api_data = resp.json()
            else:
                print(resp.status_code, resp.reason)
                sys.exit(1)
        except Exception as e:
            print(e)

        server_country_list = self.get_country_list(self.api_data)
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
        self.center_on_screen()
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
        grid_layout_1 = QtWidgets.QGridLayout(central_widget_)
        grid_layout_1.setObjectName("grid_layout_1")
        vertical_layout_5 = QtWidgets.QVBoxLayout()
        vertical_layout_5.setObjectName("vertical_layout_5")
        self.nordImageWidget = QtWidgets.QLabel(central_widget_)
        self.nordImageWidget.setObjectName("nordImageWidget")
        vertical_layout_5.addWidget(self.nordImageWidget)
        horizontal_layout_3 = QtWidgets.QHBoxLayout()
        horizontal_layout_3.setObjectName("horizontal_layout_3")
        vertical_layout_1 = QtWidgets.QVBoxLayout()
        vertical_layout_1.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint
        )
        vertical_layout_1.setContentsMargins(-1, 0, -1, -1)
        vertical_layout_1.setSpacing(6)
        vertical_layout_1.setObjectName("vertical_layout_1")
        horizontal_layout_1 = QtWidgets.QHBoxLayout()
        horizontal_layout_1.setObjectName("horizontal_layout_1")
        self.usernameLabel = QtWidgets.QLabel(central_widget_)
        self.usernameLabel.setObjectName("usernameLabel")
        horizontal_layout_1.addWidget(self.usernameLabel)
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
        horizontal_layout_1.addWidget(self.user_input)
        vertical_layout_1.addLayout(horizontal_layout_1)
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
        vertical_layout_1.addLayout(horizontal_layout_2)
        horizontal_layout_3.addLayout(vertical_layout_1)
        spacer_item_4 = QtWidgets.QSpacerItem(
            57, 20, QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum
        )
        horizontal_layout_3.addItem(spacer_item_4)
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
        grid_layout_1.addLayout(vertical_layout_5, 0, 0, 1, 1)
        self.setCentralWidget(central_widget_)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        self.center_on_screen()
        self.retranslate_login_ui()
        QtCore.QMetaObject.connectSlotsByName(self)

        self.check_configs()  # do configs exist else create

        # buttons here
        self.password_input.returnPressed.connect(self.loginButton.click)
        self.loginButton.clicked.connect(self.verify_credentials)

    def check_configs(self):
        """
        Checks if config directories and files exist and creates them if they
        do not. If username is found in config, execute get_credentials()
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
                    "MAC_RANDOMIZER": "False",
                    "KILL_SWITCH": "False",
                    "AUTO_CONNECT": "False",
                }
                self.write_conf()

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
            self.statusbar.showMessage(
                "Insufficient Permissions to create config folder", 2000
            )

    def get_credentials(self):
        try:
            keyring.get_keyring()
            password = keyring.get_password("NordVPN", self.username)
            self.password_input.setText(password)
        except Exception as ex:
            self.statusbar.showMessage("Error fetching keyring", 1000)

    def write_conf(self):
        """
        Write config file.
        """

        with open(self.conf_path, "w") as configfile:
            self.config.write(configfile)

        configfile.close()

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

        if self.user_input.text() and self.password_input.text():
            self.username = self.user_input.text()
            self.password = self.password_input.text()

        else:
            self.statusbar.showMessage(
                "Username or password field cannot be empty", 2000
            )
        try:
            # Post username and password to API endpoint.
            json_data = {"username": self.username, "password": self.password}
            resp = requests.post(
                "https://api.nordvpn.com/v1/users/tokens",
                json=json_data,
                timeout=5
            )
            if resp.status_code == 201:
                self.statusbar.showMessage("Login success", 2000)
                self.repaint()
                # Check whether credentials should be saved.
                if self.rememberCheckbox.isChecked():
                    try:
                        keyring.set_password(
                            "NordVPN", self.username, self.password
                        )
                        self.config["USER"]["USER_NAME"] = self.username
                        self.write_conf()
                    except Exception as ex:
                        self.statusbar.showMessage(
                            "Error accessing keyring", 1000
                        )

                # Otherwise, delete credentials if found.
                elif keyring.get_credential("NordVPN", self.username):
                    keyring.delete_password("NordVPN", self.username)
                    self.config["USER"]["USER_NAME"] = "None"
                    self.write_conf()

                self.hide()
                self.main_ui()
            else:
                # Debug why the response failed
                print(resp.status_code, resp.reason, resp.text)
                self.statusbar.showMessage(
                    "Invalid username or password", 2000
                )

        except Exception as ex:
            self.statusbar.showMessage(
                "API Error: could not fetch token", 2000
            )

    def get_country_list(self, api_data):
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

    def get_server_categories(self, categories):
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
            name = server["name"]
            load = server["load"]
            domain = server["domain"]
            country = server["country"]
            categories, category_list = self.get_server_categories(
                server["categories"]
            )

            if name not in server_name_list and country == filtered[0] and filtered[1] in category_list:
                server_name_list.append(
                    f'{name}\n'
                    f'Load: {load}%\n'
                    f'Domain: {domain}\n'
                    f'Categories: {server_categories}'
                )

                self.domain_list.append(domain)
                server = ServerInfo(
                    name=name,
                    country=country,
                    domain=domain,
                    type=category_list,
                    load=load,
                    categories=server_categories,
                )
                self.server_info_list.append(server)

        if server_name_list:
            # Sort lists to be in the same order.

            server_name_list, self.domain_list, self.server_info_list = (
                list(x)
                for x in zip(*sorted(
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
        """

        # https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/sg173.nordvpn.com.udp.ovpn
        self.ovpn_path = None
        ovpn_url = None

        configs_path = "https://downloads.nordcdn.com/configs/files"
        if self.server_type_select.currentText() == "Obfuscated Server" and self.connection_type_select.currentText() == "UDP":
            ovpn_url = f"{configs_path}/ovpn_xor_udp/servers/"
        elif self.server_type_select.currentText() == "Obfuscated Server" and self.connection_type_select.currentText() == "TCP":
            ovpn_url = f"{configs_path}/ovpn_xor_tcp/servers/"
        elif self.server_type_select.currentText() != "Obfuscated Server" and self.connection_type_select.currentText() == "UDP":
            ovpn_url = f"{configs_path}/ovpn_udp/servers/"
        elif self.server_type_select.currentText() != "Obfuscated Server" and self.connection_type_select.currentText() == "TCP":
            ovpn_url = f"{configs_path}/ovpn_tcp/servers/"

        current_server = self.domain_list[self.server_list.currentRow()]
        if self.connection_type_select.currentText() == "UDP":
            filename = f'{current_server}.udp.ovpn'
        elif self.connection_type_select.currentText() == "TCP":
            filename = f'{current_server}.tcp.ovpn'

        ovpn_file = requests.get(ovpn_url + filename, stream=True)
        if ovpn_file.status_code == requests.codes.ok:
            self.ovpn_path = os.path.join(self.config_path, filename)
            with open(self.ovpn_path, "wb") as out_file:
                shutil.copyfileobj(ovpn_file.raw, out_file)
        else:
            self.statusbar.showMessage(
                "Error fetching configuration files", 2000
            )

        self.server_list.setFocus()

    def import_ovpn(self):
        """
        Rename and import OVPN file to NetworkManager and clean up temp files.
        """

        try:
            self.statusbar.showMessage("Importing Connection...")
            self.repaint()
            self.connection_name = self.generate_connection_name()
            ovpn_file = f'{self.connection_name}.ovpn'

            # changes name from default
            path = os.path.join(self.config_path, ovpn_file)
            shutil.copy(self.ovpn_path, path)
            os.remove(self.ovpn_path)
            output = subprocess.run(
                ["nmcli", "connection", "import", "type", "openvpn", "file", path]
            )
            output.check_returncode()
            os.remove(path)

        except subprocess.CalledProcessError:
            self.statusbar.showMessage("ERROR: Importing VPN configuration")

    def run_nmcli(self, config_option, config_value):
        try:
            process = subprocess.run([
                "nmcli",
                "connection",
                "modify",
                self.connection_name,
                config_option,
                config_value,
            ])
            process.check_returncode()
            return process
        except subprocess.CalledProcessError:
            self.statusbar.showMessage("ERROR: nmcli command failed", 2000)

    def add_secrets(self):
        """
        Add the username and password to the NetworkManager configuration.
        """

        self.statusbar.showMessage("Adding Secrets...", 1000)
        self.repaint()

        password_flag = self.run_nmcli("+vpn.data", "password-flags=0")
        secrets = self.run_nmcli("+vpn.secrets", f'password={self.password}')
        user_secret = self.run_nmcli("+vpn.data", f'username={self.username}')
        disable_ipv6 = self.run_nmcli("+ipv6.method", "ignore")
        password_flag = self.run_nmcli("+vpn.data", "password-flags=0")

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

    def get_connection_info(self, connection_info):
        server_name = ''
        server_type = 0
        print(connection_info)

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

        print(server_name, server_type)
        return server_name, server_type

    def get_active_vpn(self):
        """
        Query NetworkManager for the current connection.
        If a current connection is found, set the UI to the appropriate state.

        :return Bool
        """

        try:
            output = subprocess.run(
                [
                    "nmcli",
                    "--mode",
                    "tabular",
                    "--terse",
                    "--fields",
                    "TYPE,NAME",
                    "connection",
                    "show",
                    "--active",
                ],
                stdout=subprocess.PIPE,
            )
            output.check_returncode()

            for line in output.stdout.decode("utf-8").split("\n"):
                try:
                    elements = line.strip().split(":")
                    connection_name = elements[1]
                    connection_info = connection_name.split()
                    country = connection_info[0]
                    server_name, server_type = self.get_connection_info(
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
                        self.statusbar.showMessage(
                            "Fetching Active Server...", 2000
                        )
                        self.repaint()
                        item = self.country_list.findItems(
                            country, QtCore.Qt.MatchExactly
                        )
                        self.country_list.setCurrentItem(item[0])

                        self.server_type_select.setCurrentIndex(server_type)

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
            self.statusbar.showMessage(
                "ERROR: Network Manager query error", 2000
            )
            self.repaint()

    def randomize_mac(self):
        """
        Take down network interface and bring it back with a new MAC address.
        """

        try:
            self.statusbar.showMessage("Randomizing MAC Address", 2000)
            self.repaint()
            output = subprocess.run(
                [
                    "nmcli",
                    "--mode",
                    "tabular",
                    "--terse",
                    "--fields",
                    "TYPE,UUID",
                    "connection",
                    "show",
                    "--active",
                ],
                stdout=subprocess.PIPE,
            )
            output.check_returncode()
            lines = output.stdout.decode("utf-8").split("\n")

            for line in lines:
                elements = line.strip().split(":")
                uuid = elements[1]
                connection_type = elements[0]
                if type != "vpn":
                    subprocess.run(["nmcli", "connection", "down", uuid])
                    subprocess.run(
                        [
                            "nmcli",
                            "connection",
                            "modify",
                            "--temporary",
                            uuid,
                            f'{connection_type}.cloned-mac-address',
                            "random",
                        ]
                    )

                    subprocess.run(["nmcli", "connection", "up", uuid])

            self.statusbar.showMessage("Random MAC Address assigned", 2000)
            self.write_conf()
            self.repaint()
        except subprocess.CalledProcessError:
            self.statusbar.showMessage("ERROR: Randomizer failed", 2000)
            self.repaint()

    def get_sudo(self):
        """
        Sudo dialog UI form
        TODO: Remove in favour of a DBUS based approach
        """

        sudo_dialog = QtWidgets.QDialog(self)
        sudo_dialog.setModal(True)
        sudo_dialog.resize(399, 206)
        icon = QtGui.QIcon.fromTheme("changes-prevent")
        sudo_dialog.setWindowIcon(icon)
        sudo_dialog_grid_layout = QtWidgets.QGridLayout(sudo_dialog)
        sudo_dialog_grid_layout.setObjectName("sudo_dialog_grid_layout")
        sudo_dialog_vertical_layout = QtWidgets.QVBoxLayout()
        sudo_dialog_vertical_layout.setContentsMargins(-1, 18, -1, -1)
        sudo_dialog_vertical_layout.setSpacing(16)
        sudo_dialog_vertical_layout.setObjectName(
            "sudo_dialog_vertical_layout"
        )
        sudo_dialog_text_label = QtWidgets.QLabel(sudo_dialog)
        sudo_dialog_text_label.setTextFormat(QtCore.Qt.RichText)
        sudo_dialog_text_label.setAlignment(
            QtCore.Qt.AlignLeading | QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter
        )
        sudo_dialog_text_label.setWordWrap(True)
        sudo_dialog_text_label.setObjectName("sudo_dialog_text_label")
        sudo_dialog_vertical_layout.addWidget(sudo_dialog_text_label)
        sudo_dialog_password = QtWidgets.QLineEdit(self)
        sudo_dialog_password.setCursor(
            QtGui.QCursor(QtCore.Qt.IBeamCursor)
        )
        sudo_dialog_password.setAlignment(QtCore.Qt.AlignCenter)
        sudo_dialog_password.setClearButtonEnabled(False)
        sudo_dialog_password.setObjectName("sudo_dialog_password")
        sudo_dialog_password.setEchoMode(QtWidgets.QLineEdit.Password)
        sudo_dialog_vertical_layout.addWidget(sudo_dialog_password)
        sudo_dialog_grid_layout.addLayout(
            sudo_dialog_vertical_layout, 0, 0, 1, 1
        )
        sudo_dialog_layout = QtWidgets.QHBoxLayout()
        sudo_dialog_layout.setSizeConstraint(
            QtWidgets.QLayout.SetDefaultConstraint
        )
        sudo_dialog_layout.setContentsMargins(-1, 0, -1, 6)
        sudo_dialog_layout.setSpacing(0)
        sudo_dialog_layout.setObjectName("sudo_dialog_layout")
        spacer_item_5 = QtWidgets.QSpacerItem(
            178, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum
        )
        sudo_dialog_layout.addItem(spacer_item_5)
        sudo_dialog_accept_box = QtWidgets.QDialogButtonBox(sudo_dialog)
        sudo_dialog_accept_box.setOrientation(QtCore.Qt.Horizontal)
        sudo_dialog_accept_box.addButton(
            "Login", QtWidgets.QDialogButtonBox.AcceptRole
        )
        sudo_dialog_accept_box.addButton(
            "Cancel", QtWidgets.QDialogButtonBox.RejectRole
        )
        sudo_dialog_accept_box.setObjectName("sudo_dialog_accept_box")
        sudo_dialog_layout.addWidget(sudo_dialog_accept_box)
        sudo_dialog_grid_layout.addLayout(
            sudo_dialog_layout, 1, 0, 1, 1
        )
        sudo_dialog.setWindowTitle("Authentication needed")
        sudo_dialog_text_label.setText(
            '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions in order to move the auto-connect script to the Network Manager directory. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated priveledges.</p></body></html>'
        )
        resolution = QtWidgets.QDesktopWidget().screenGeometry()
        # move to center
        sudo_dialog.move(
            int(
                (
                    resolution.width() / 2
                ) - (
                    sudo_dialog.frameSize().width() / 2
                )
            ),
            int(
                (
                    resolution.height() / 2
                ) - (
                    sudo_dialog.frameSize().height() / 2
                )
            ),
        )
        # button functionality here
        sudo_dialog_accept_box.accepted.connect(self.check_sudo)
        sudo_dialog_accept_box.rejected.connect(self.close_sudo_dialog)
        QtCore.QMetaObject.connectSlotsByName(sudo_dialog)
        return sudo_dialog

    def close_sudo_dialog(self):
        # Clear sudo password when cancel is pressed.

        self.sudo_password = None
        self.sudo_dialog.close()

    def check_sudo(self):
        """
        Check validity of sudo password.

        :return: True if valid False if invalid
        """

        self.sudo_password = self.sudo_dialog_password.text()
        try:
            p1 = subprocess.Popen(
                ["echo", self.sudo_password],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p2 = subprocess.Popen(
                ["sudo", "-S", "whoami"],
                stdin=p1.stdout,
                stdout=subprocess.PIPE,
                encoding="utf-8",
                stderr=subprocess.PIPE,
            )
            p1.stdout.close()
            output = p2.communicate()[0].strip()
            p2.stdout.close()

            if "root" in output:
                self.sudo_dialog.close()
                print("True")
                return True
            else:
                error = QtWidgets.QErrorMessage(self.sudo_dialog)
                error.showMessage("Invalid Password")
                return False
        except Exception as ex:
            print("failed", ex)
            self.sudo_password = None

    def get_interfaces(self):
        """
        Get current network interfaces.

        :return: List of network interfaces
        """

        try:
            output = subprocess.run(
                [
                    "nmcli",
                    "--mode",
                    "tabular",
                    "--terse",
                    "--fields",
                    "TYPE,DEVICE",
                    "device",
                    "status",
                ],
                stdout=subprocess.PIPE,
            )
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
            self.statusbar.showMessage("ERROR Fetching interfaces")

    def set_auto_connect(self):
        """
        Generate auto_connect bash script and move it to NetworkManager.
        """

        self.config.read(self.conf_path)
        if interfaces := self.get_interfaces():
            interface_string = "|".join(interfaces)
            script = (
                "#!/bin/bash\n\n"
                'if [[ "$1" =~ '
                + interface_string
                + ' ]] && [[ "$2" =~ up|connectivity-change ]]; then\n'
                '  nmcli con up id "' + self.generate_connection_name() + '"\n'
                "fi\n"
            )
        try:
            with open(
                os.path.join(self.scripts_path, "auto_connect"), "w"
            ) as auto_connect:
                print(script, file=auto_connect)
        except Exception as ex:
            print(ex)
            self.statusbar.showMessage("ERROR building script file")
        try:
            p1 = subprocess.Popen(
                ["echo", self.sudo_password],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p2 = subprocess.Popen(
                [
                    "sudo",
                    "-S",
                    "mv",
                    f'{self.scripts_path}/auto_connect',
                    f'{self.network_manager_path}auto_connect',
                ],
                stdin=p1.stdout,
                stdout=subprocess.PIPE,
            )

            p1.stdout.close()
            p2.stdout.close()
            p3 = subprocess.Popen(
                ["echo", self.sudo_password],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p4 = subprocess.Popen(
                [
                    "sudo",
                    "-S",
                    "chown",
                    "root:root",
                    f'{self.network_manager_path}auto_connect',
                ],
                stdin=p3.stdout,
                stdout=subprocess.PIPE,
            )

            p3.stdout.close()
            p4.stdout.close()
            p5 = subprocess.Popen(
                ["echo", self.sudo_password],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p6 = subprocess.Popen(
                [
                    "sudo",
                    "-S",
                    "chmod",
                    "744",
                    f'{self.network_manager_path}auto_connect',
                ],
                stdin=p5.stdout,
                stdout=subprocess.PIPE,
            )

            p5.stdout.close()
            p6.stdout.close()
            self.config["SETTINGS"]["auto_connect"] = "True"
            self.write_conf()
        except Exception as ex:
            print(ex)

    def disable_auto_connect(self):
        """
        Handles the enabling and disabling of auto-connect depending on UI state
        Called everytime the auto-connect box is clicked
        """
        self.config.read(self.conf_path)

        if not self.auto_connect_box.isChecked() and not self.sudo_password and self.config.getboolean("SETTINGS", "auto_connect"):
            self.sudo_dialog = self.get_sudo()
            self.sudo_dialog_text_label.setText(
                '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions in order to remove the auto-connect script from the Network Manager directory. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated priveledges.</p></body></html>'
            )
            self.sudo_dialog.exec_()
            if not self.sudo_password:  # dialog was canceled
                return False
            try:
                p1 = subprocess.Popen(
                    ["echo", self.sudo_password],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                p2 = subprocess.Popen(
                    [
                        "sudo",
                        "-S",
                        "rm",
                        f'{self.network_manager_path}auto_connect',
                    ],
                    stdin=p1.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                p1.stdout.close()
                p2.stdout.close()
                self.config["SETTINGS"]["auto_connect"] = "False"
                self.write_conf()
            except Exception as ex:
                print(ex)

        elif not self.auto_connect_box.isChecked() and self.sudo_password and self.config.getboolean("SETTINGS", "auto_connect"):
            try:
                p1 = subprocess.Popen(
                    ["echo", self.sudo_password],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                p2 = subprocess.Popen(
                    [
                        "sudo",
                        "-S",
                        "rm",
                        f'{self.network_manager_path}auto_connect',
                    ],
                    stdin=p1.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                p1.stdout.close()
                p2.stdout.close()
                self.config["SETTINGS"]["auto_connect"] = "False"
                self.write_conf()
            except Exception as ex:
                print(ex)
        elif self.auto_connect_box.isChecked() and self.get_active_vpn() and self.sudo_password:
            self.set_auto_connect()

        elif self.auto_connect_box.isChecked() and self.get_active_vpn() and not self.sudo_password:
            self.sudo_dialog = self.get_sudo()
            self.sudo_dialog.exec_()
            if self.sudo_password:
                self.set_auto_connect()
            else:
                self.auto_connect_box.setChecked(False)
                return False

    def set_kill_switch(self):
        """
        Generate bash kill switch script and move it to NetworkManager.
        """

        script = (
            "#!/bin/bash\n"
            "PERSISTENCE_FILE="
            + os.path.join(self.scripts_path, ".killswitch_data")
            + "\n\n"
            "case $2 in"
            "  vpn-up)\n"
            "    nmcli -f type,device connection | awk '$1~/^vpn$/ && $2~/[^\-][^\-]/ { print $2; }' > \"${PERSISTENCE_FILE}\"\n"
            "  ;;\n"
            "  vpn-down)\n"
            '    xargs -n 1 -a "${PERSISTENCE_FILE}" nmcli device disconnect\n'
            "  ;;\n"
            "esac\n"
        )

        try:
            with open(
                os.path.join(self.scripts_path, "kill_switch"), "w"
            ) as kill_switch:
                print(script, file=kill_switch)

            p1 = subprocess.Popen(
                ["echo", self.sudo_password],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            p2 = subprocess.Popen(
                [
                    "sudo",
                    "-S",
                    "mv",
                    f'{self.scripts_path}/kill_switch',
                    f'{self.network_manager_path}kill_switch',
                ],
                stdin=p1.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            p1.stdout.close()
            p2.stdout.close()
            time.sleep(0.5)
            p3 = subprocess.Popen(
                ["echo", self.sudo_password],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            p4 = subprocess.Popen(
                [
                    "sudo",
                    "-S",
                    "chown",
                    "root:root",
                    f'{self.network_manager_path}kill_switch',
                ],
                stdin=p3.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            time.sleep(0.5)
            p3.stdout.close()
            p4.stdout.close()
            p5 = subprocess.Popen(
                ["echo", self.sudo_password],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            p6 = subprocess.Popen(
                [
                    "sudo",
                    "-S",
                    "chmod",
                    "744",
                    f'{self.network_manager_path}kill_switch',
                ],
                stdin=p5.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            p5.stdout.close()
            p6.stdout.close()
            self.config["SETTINGS"]["kill_switch"] = "True"
            self.write_conf()
            self.statusbar.showMessage("Kill switch activated", 2000)
            self.repaint()
        except Exception as ex:
            print(ex)

    def disable_kill_switch(self):
        """
        Enables or disables Killswitch depending on UI state
        Called everytime the Killswitch button is pressed
        """
        if not self.kill_switch_button.isChecked() and not self.sudo_password and self.config.getboolean("SETTINGS", "kill_switch"):
            self.sudo_dialog = self.get_sudo()
            self.sudo_dialog_text_label.setText(
                '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions in order to remove the kill switch script from the Network Manager directory. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated priveledges.</p></body></html>'
            )
            self.sudo_dialog.exec_()

            if not self.sudo_password:  # dialog was canceled
                self.kill_switch_button.setChecked(False)
                return False
            try:
                p1 = subprocess.Popen(
                    ["echo", self.sudo_password],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                )
                p2 = subprocess.Popen(
                    [
                        "sudo",
                        "-S",
                        "rm",
                        f'{self.network_manager_path}kill_switch',
                    ],
                    stdin=p1.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                p1.stdout.close()
                p2.stdout.close()
                self.statusbar.showMessage("Kill switch disabled", 2000)
                self.repaint()
                self.config["SETTINGS"]["kill_switch"] = "False"
                self.write_conf()

            except subprocess.CalledProcessError:
                self.statusbar.showMessage("ERROR disabling kill switch", 2000)
                self.repaint()

        elif (
            not self.kill_switch_button.isChecked()
            and self.sudo_password
            and self.config.getboolean("SETTINGS", "kill_switch")
        ):

            try:
                p1 = subprocess.Popen(
                    ["echo", self.sudo_password],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                )
                p2 = subprocess.Popen(
                    [
                        "sudo",
                        "-S",
                        "rm",
                        f'{self.network_manager_path}kill_switch',
                    ],
                    stdin=p1.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                p1.stdout.close()
                p2.stdout.close()
                self.statusbar.showMessage("Kill switch disabled", 2000)
                self.repaint()
                self.config["SETTINGS"]["kill_switch"] = "False"
                self.write_conf()

            except subprocess.CalledProcessError:
                self.statusbar.showMessage("ERROR disabling kill switch", 2000)
                self.repaint()

        elif self.kill_switch_button.isChecked() and self.get_active_vpn() and self.sudo_password:
            self.set_kill_switch()

        elif self.kill_switch_button.isChecked() and self.get_active_vpn() and not self.sudo_password:
            self.sudo_dialog = self.get_sudo()
            self.sudo_dialog_text_label.setText(
                '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions in order to move the kill switch script to the Network Manager directory. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated priveledges.</p></body></html>'
            )
            self.sudo_dialog.exec_()
            if self.sudo_password:
                self.set_kill_switch()
            else:
                self.kill_switch_button.setChecked(False)
                return False

    def disable_ipv6(self):
        """
        Disables IPV6 system wide
        """
        if self.sudo_password:
            try:
                p1 = subprocess.Popen(
                    ["echo", self.sudo_password],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                )
                p2 = subprocess.Popen(
                    [
                        "sudo",
                        "-S",
                        "sysctl",
                        "-w",
                        "net.ipv6.conf.all.disable_ipv6=1",
                        "&&",
                        "sysctl",
                        "-w",
                        "net.ipv6.conf.default.disable_ipv6=1",
                    ],
                    stdin=p1.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                p1.stdout.close()
                p2.stdout.close()
            except subprocess.CalledProcessError:
                self.statusbar.showMessage(
                    "ERROR: disabling IPV6 failed", 2000
                )
        else:
            self.sudo_dialog = self.get_sudo()
            self.sudo_dialog_text_label.setText(
                '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions in order to disable IPV6. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated priveledges.</p></body></html>'
            )
            self.sudo_dialog.exec_()

            if self.sudo_password:
                try:
                    p1 = subprocess.Popen(
                        ["echo", self.sudo_password],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                    )
                    p2 = subprocess.Popen(
                        [
                            "sudo",
                            "-S",
                            "sysctl",
                            "-w",
                            "net.ipv6.conf.all.disable_ipv6=1",
                            "&&",
                            "sysctl",
                            "-w",
                            "net.ipv6.conf.default.disable_ipv6=0",
                        ],
                        stdin=p1.stdout,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    p1.stdout.close()
                    p2.stdout.close()
                except subprocess.CalledProcessError:
                    self.statusbar.showMessage(
                        "ERROR: disabling IPV6 failed", 2000
                    )

    def enable_ipv6(self):
        """
        Re-enables ipv6 system wide
        """
        if self.sudo_password:
            try:
                p1 = subprocess.Popen(
                    ["echo", self.sudo_password],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                )
                p2 = subprocess.Popen(
                    [
                        "sudo",
                        "-S",
                        "sysctl",
                        "-w",
                        "net.ipv6.conf.all.disable_ipv6=0",
                        "&&",
                        "sysctl",
                        "-w",
                        "net.ipv6.conf.default.disable_ipv6=0",
                    ],
                    stdin=p1.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                p1.stdout.close()
                p2.stdout.close()
            except subprocess.CalledProcessError:
                self.statusbar.showMessage(
                    "ERROR: disabling IPV6 failed", 2000)
        else:
            self.sudo_dialog = self.get_sudo()
            self.sudo_dialog_text_label.setText(
                '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions in order to enable IPV6. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated priveledges.</p></body></html>'
            )
            self.sudo_dialog.exec_()

            if self.sudo_password:
                try:
                    p1 = subprocess.Popen(
                        ["echo", self.sudo_password],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                    )
                    p2 = subprocess.Popen(
                        [
                            "sudo",
                            "-S",
                            "sysctl",
                            "-w",
                            "net.ipv6.conf.all.disable_ipv6=0",
                            "&&",
                            "sysctl",
                            "-w",
                            "net.ipv6.conf.default.disable_ipv6=0",
                        ],
                        stdin=p1.stdout,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    p1.stdout.close()
                    p2.stdout.close()
                except subprocess.CalledProcessError:
                    self.statusbar.showMessage(
                        "ERROR: Enabling IPV6 failed", 2000)

    def check_connection_validity(self):
        """
        Checks if connection is a double_vpn and forces the connection to TCP
        """
        if (
            self.server_type_select.currentText() == "Double VPN"
        ):  # perhaps add pop up to give user the choice
            self.connection_type_select.setCurrentIndex(1)  # set to TCP

    def enable_connection(self):
        """
        Enable vpn connection in NetworkManager
        """
        try:
            self.statusbar.showMessage("Connecting...", 1000)
            self.repaint()
            connection = subprocess.run(
                ["nmcli", "connection", "up", self.connection_name]
            )
            connection.check_returncode()
        except subprocess.CalledProcessError:
            self.statusbar.showMessage("ERROR: Connection Failed", 2000)

    def disable_connection(self):
        """
        Disconnect vpn connection in NetworkManager
        """
        try:
            self.statusbar.showMessage("Disconnecting...", 1000)
            self.repaint()
            connection = subprocess.run(
                ["nmcli", "connection", "down", self.connection_name]
            )
            connection.check_returncode()
        except subprocess.CalledProcessError:
            self.statusbar.showMessage("ERROR: Disconnection Failed", 2000)

    def remove_connection(self):
        """
        Remove connection from network manager
        """
        try:
            connection = subprocess.run(
                ["nmcli", "connection", "delete", self.connection_name]
            )
            connection.check_returncode()
        except subprocess.CalledProcessError:
            self.statusbar.showMessage(
                "ERROR: Failed to remove Connection", 2000)

    def connect(self):
        """
        Step through all of the UI Logic for connecting to the VPN.
        """

        if self.mac_changer_box.isChecked():
            self.randomize_mac()
            self.config["SETTINGS"]["mac_randomizer"] = "True"
        else:
            self.config["SETTINGS"]["mac_randomizer"] = "False"
        self.write_conf()
        if self.auto_connect_box.isChecked():
            if not self.sudo_password:  # prompt for sudo password
                self.sudo_dialog = self.get_sudo()
                self.sudo_dialog.exec_()

                if self.sudo_password:  # valid password exists
                    self.set_auto_connect()
                else:
                    self.auto_connect_box.setChecked(False)
                    return False
            else:
                self.set_auto_connect()
        self.check_connection_validity()
        self.disable_ipv6()
        self.get_ovpn()
        self.import_ovpn()
        self.add_secrets()
        self.enable_connection()
        self.statusbar.clearMessage()
        self.repaint()

        if self.kill_switch_button.isChecked():
            if not self.sudo_password:
                self.sudo_dialog = self.get_sudo()
                self.sudo_dialog_text_label.setText(
                    '<html><head/><body><p>VPN Network Manager requires <span style=" font-weight:600;">sudo</span> permissions in order to move the kill switch script to the Network Manager directory. Please input the <span style=" font-weight:600;">sudo</span> Password or run the program with elevated priveledges.</p></body></html>'
                )
                self.sudo_dialog.exec_()
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
            time.sleep(
                5
            )  # sleep time to mitigate NetworkManager still killing connection
        if self.auto_connect_box.isChecked():
            self.auto_connect_box.setChecked(False)
            self.statusbar.showMessage("Disabling auto-connect...", 1000)
            self.disable_auto_connect()
        self.disable_connection()
        self.remove_connection()
        self.enable_ipv6()
        self.statusbar.clearMessage()
        self.repaint()

        # UI changes here
        self.disconnect_button.hide()
        self.connect_button.show()
        self.retranslateUi()

    def center_on_screen(self):
        """
        Find the center of the user's screen.
        """

        resolution = QtWidgets.QDesktopWidget().screenGeometry()
        self.move(
            int((resolution.width() / 2) - (self.frameSize().width() / 2)),
            int((resolution.height() / 2) - (self.frameSize().height() / 2)),
        )

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", " "))
        self.title_label.setText(
            _translate(
                "MainWindow",
                f'<html><head/><body><p align="center"><img src="{os.path.dirname(__file__)}/assets/nord-logo.png"/></p></body></html>',
            )
        )
        self.country_list_label.setText(_translate("MainWindow", "Countries"))
        self.auto_connect_box.setStatusTip(
            _translate(
                "MainWindow", "Network Manager will auto-connect on system start"
            )
        )
        self.auto_connect_box.setText(_translate("MainWindow", "Auto connect"))
        self.mac_changer_box.setStatusTip(
            _translate("MainWindow", "Randomize MAC address")
        )
        self.mac_changer_box.setText(_translate("MainWindow", "Randomize MAC"))
        self.kill_switch_button.setStatusTip(
            _translate(
                "MainWindow", "Disables internet connection if VPN connectivity is lost"
            )
        )
        self.kill_switch_button.setText(
            _translate("MainWindow", "Kill Switch"))
        self.server_type_select.setStatusTip(
            _translate("MainWindow", "Select Server Type")
        )
        self.connection_type_select.setStatusTip(
            _translate("MainWindow", "Select connection type")
        )
        self.connect_button.setText(_translate("MainWindow", "Connect"))
        self.disconnect_button.setText(_translate("MainWindow", "Disconnect"))
        self.central_widget_label.setText(_translate("MainWindow", "Servers"))

    def retranslate_login_ui(self):
        _translate = QtCore.QCoreApplication.translate
        self.nordImageWidget.setText(
            _translate(
                "MainWindow",
                f'<html><head/><body><p align="center"><img src="{os.path.dirname(__file__)}/assets/nordvpnicon.png"/></p><p align="center"><br/></p></body></html>',
            )
        )
        self.usernameLabel.setText(
            _translate(
                "MainWindow",
                '<html><head/><body><p align="right">Email:     </p></body></html>',
            )
        )
        self.passwordLabel.setText(
            _translate(
                "MainWindow",
                '<html><head/><body><p align="right">Password:     </p></body></html>',
            )
        )
        self.loginButton.setText(_translate("MainWindow", "Login"))
        self.rememberCheckbox.setText(_translate("MainWindow", "Remember"))


def main():
    app_name = "NordVPN"
    prctl.set_name(app_name)
    prctl.set_proctitle(app_name)
    app = QtWidgets.QApplication(sys.argv)
    ui = MainWindow()
    sys.exit(app.exec_())
