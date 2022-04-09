# NordVPN Network Manager GUI

[![License badge](https://img.shields.io/github/license/vfosterm/NordVPN-NetworkManager-Gui?style=for-the-badge)](https://github.com/vfosterm/NordVPN-NetworkManager-Gui/blob/master/LICENSE)
[![Issues](https://img.shields.io/github/issues-closed/vfosterm/NordVPN-NetworkManager-Gui?style=for-the-badge)](https://github.com/vfosterm/NordVPN-NetworkManager-Gui/issues)
[![Release](https://img.shields.io/github/release/vfosterm/NordVPN-NetworkManager-Gui?style=for-the-badge)](https://github.com/vfosterm/NordVPN-NetworkManager-Gui/releases/latest)
[![commits-since](https://img.shields.io/github/commits-since/vfosterm/NordVPN-NetworkManager-Gui/latest?style=for-the-badge)](https://github.com/vfosterm/NordVPN-NetworkManager-Gui/commits/master)
[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://python.org)

![Login screen](nord_nm_gui/assets/login_new.png)

![Main screen](nord_nm_gui/assets/main_new.png)

## About

NordVPN Network Manager GUI is a graphical frontend for both NordVPN and the
system Network Manager. All connections are handled directly by the network
manager and user secrets are only stored in memory before being passed to the
Network Manager. Currently it operates 100% as a user process with no need for
root privileges.

This project was inspired by
[NordVPN-NetworkManager](https://github.com/Chadsr/NordVPN-NetworkManager) by
Chadsr. Many thanks for the code and knowledge that they published into the
public domain.

## Features

-   Light - Uses the system Network Manager, application doesn't need to be running
-   Clean - All configuration files are deleted after disconnection
-   Secure - User secrets are passed directly from memory to the Network
    manager, root access is not required
-   Powerful - Supports a variety of different protocols and server types with
    more on the way.
-   Kill Switch - internet connection is disabled if VPN connection is lost
-   Auto Connect - VPN is connection is established on system start
-   Randomize MAC - Random MAC address is assigned before establishing connection

## Known issues

-   No support for obfuscated servers

## TODO

1.  ~Poetry~
2.  ~Pre-commit and other linting~
3.  ~Split helper functions out of GUI class~
4.  ~Stop spamming API - dry run by getting JSON once and then commenting calls~
5.  ~Fix GUI bugs~
6.  Move NM calls to a Python binding instead of shelling out with `subprocess`
7.  Handle sudo properly
8.  Use standard XDG paths / libraries for handling config paths
9.  ~Use a config option to bypass Nord API calls~
10.  Add a map selector
11.  Upstream

## WARNING

Make sure to disable webrtc in your browser of choice. Using WebRTC may leak
your original IP address.
