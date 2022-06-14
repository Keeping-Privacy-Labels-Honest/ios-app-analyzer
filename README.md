# ios-app-analyzer

This tool allows for the collection of traffic data using a jailbroken iPhone.

## requirements

- node
- yarn
- python
- postgres
- sshpass
- libimobiledevice
  - **configure** according to notes.md!

## iPhone Setup

* Jailbreak (checkra1n)
* mitmproxy section
* Enable SSH server 
    - Install packages frida, OpenSSH, Open, Sqlite3 from Cydia
    - Connect using `root@<ip>`, password `alpine`
* Settings
    - Display & Brightness -> Auto-Lock -> Never
* Install [Activator](https://cydia.saurik.com/package/libactivator/)

### Settings:

* General
    - Background App Refresh: off (to hopefully minimize background network traffic)
* Privacy
    - Analytics & Improvements
        * Share iPhone Analytics: off
    - Apple Advertising
        * Personalised Ads: on (default)
* App Store
    - Automatic Downloads
        * Apps: off
        * App Updates: off

* Turn on Bluetooth.
* Uninstall all third-party apps that are not absolutely necessary.

### Set up mitmproxy

* Setup: https://www.andyibanez.com/posts/intercepting-network-mitmproxy/#physical-ios-devices
* https://github.com/nabla-c0d3/ssl-kill-switch2 (https://steipete.com/posts/jailbreaking-for-ios-developers/#ssl-kill-switch)
    - Install Debian Packager, Cydia Substrate, PreferenceLoader and Filza from Cydia.
    - Download latest release: https://github.com/nabla-c0d3/ssl-kill-switch2/releases
    - In Filza, go to `/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/Downloads` and install.
    - Respring.
    - Enable in Settings under SSL Kill Switch 2.


### Device preparation

- **Make sure that frida version on the iPhone matches the js lib!**
- configure proxy, connect iphone via usb


## Installation

- setup postgres (create database: `mergeSchema.sql`)
- create .env on top-level:

  - ```env
    POSTGRES_DB=ios
    POSTGRES_USER=ios
    POSTGRES_PASSWORD=<password>
    HOST_PORT=5432

    ```

- `cd src`
- `yarn` for js dependencies
- python deps:
  - ```sh
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```


## Running

```
node src/run.js /path/to/the/folder/containing/the/app.ipa(s)
```