# Jumper BLE Logger
## Introduction
The BLE Logger is part of Jumper Insights. A full visibility platform for IoT systems.
The BLE Logger logs data from a BLE peripheral and sends it to Jumper's cloud system.

## Prerequisites
**Gateway:**

- Linux machine as a central BLE device
- Python2.7 and Pip installed
- Jumper's Logging Agent should be installed and running
- LE connection to the BLE peripheral

**Peripherals**

- Jumper's uLogger should be installed
- Currently, only GATT protocol is supported.

## Getting Started
Check out our sample project for the Nordic nRF52 development kit.

## How it Works
*If you just want to get started, feel free to skip this step*

When the BLE Logger is started, it will connect to your current HCI device (usually "hci0") and will create a new 
proxied HCI device (usually "hci1") which you will set your gateway program to connect to.

The new "hci1" device can be used just like the original "hci0", as all commands and events will transparently pass on to it.
When logging notifications are received from the peripheral, the BLE Logger will send them to Jumper's Logging Agent and will not pass them on to "hci1" (gateway program).

This is the process of how it works (GATT only):

1. The BLE Logger recognizes established LE connections.
2. When the gateway program is discovering characteristics, the BLE Logger recognizes Jumper's GATT service.
3. The BLE Logger reads the current timestamp from the device and synchronizes it with the real world time.
4. The BLE Logger writes to the notifications handle to enable logging notifications.
5. When a logging notification is being received, the BLE Logger will write it to the Logging Agent.

The user/gateway program is not being affected by steps 3-4 and they are being filtered out from 'hci1'

## Installation
`sudo pip install https://github.com/Jumperr-labs/jumper-ble-logger/archive/v0.0.1.tar.gz`

## Usage
- Make sure Jumper's Logging Agent is running
`sudo service jumper-agent start`
- Create a config file of a JSON format such as _"config_sample.json"_
- Run `hciconfig` and check your current available HCI devices
- Start the BLE Logger: `jumper-ble-logger --config-file config_sample.json`
- Run `hciconfig` again to see your newly created HCI device
- Connect your gateway program to the newly created HCI device. The BLE Logger will start logging as soon as you connect to a peripheral and discover its characteristics.

## Contact Us
We are happy to help! Feel free to contact us about any issue and give us your feedback at [info@jumper.io](mailto:info@jumper.io)
