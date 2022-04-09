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

## Configuration

The program looks for `~/.nornconfigs/.configs/nord_settings.conf` and will
create it if not present. This contains the following structure:

```cfg
[USER]
user_name = user@email.com

[SETTINGS]
mac_randomizer = false
kill_switch = false
auto_connect = false
json_path = /path/to/api_data.json
```

If `json_path` is specified the the program will skip authenticating against
the NordVPN API and fetching the API data json on startup: this is because this
API has rate-limiting and hitting it constantly will result in rejections. The
credentials used on login are still used to actually authenticate VPN
connections, so should still be entered.

## Known issues

-   No support for obfuscated servers

## TODO

-   ~Poetry~
-   ~Pre-commit and other linting~
-   ~Split helper functions out of GUI class~
-   ~Stop spamming API: dry run by getting JSON once and then commenting calls~
-   ~Fix GUI bugs~
-   ~Use a config option to bypass Nord API calls~
-   ~Change the option to bypass the API so it passes a path for the JSON file~
-   Convert `print()`s to either status bar / taskbar notices or proper logging
-   Move NM calls to a Python binding instead of shelling out with `subprocess`
-   Handle sudo properly
-   Use `xdg` for handling config paths
-   Fix the .desktop icon path to be generic or put the icon where it's needed
-   Add a map selector
-   Upstream

## WARNING

Make sure to disable webrtc in your browser of choice. Using WebRTC may leak
your original IP address.
