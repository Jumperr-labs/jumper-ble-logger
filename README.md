# Jumper BLE Logger

## Introduction
The BLE Logger seamlessly logs data from a BLE peripheral with Jumper's uLogger installed.
When the BLE Logger is started, it will connect to your current HCI device (usually "hci0") and will create a new 
proxied HCI device (usually "hci1") which you will set your gateway program to connect to.

The new "hci1" device can be used just like the original "hci0", as all commands and events will transparently pass onto it.
When logging notifications are received from the peripheral, the BLE Logger will send them to Jumper's Logging Agent 
and will not pass them on to "hci1" (gateway program).

Currently, only GATT protocol is supported.

This is the process of how it works (GATT only):
1. The BLE Logger recognizes established LE connections.
2. When the gateway program is discovering characteristics, the BLE Logger recognizes Jumper's GATT service.
3. The BLE Logger writes to the notifications handle to enable logging notifications.
4. When a logging notification is being received, the BLE logger will write it to the Logging Agent.

The user/gateway program is not being affected by steps 3-4 and they are being filtered out from 'hci1'

## Prerequisites
**Gateway:**
    - Linux machine as a central BLE device
    - Jumper's Logging Agent should be installed and running
    - LE connection to the BLE peripheral
**Peripherals**
    - Jumper's uLogger should be installed

## Installation
`pip install BLABLABLA`

## Usage
- Make sure Jumper's Logging Agent is running
- Run the following command: `python -m BLABLBABLBALBALBALB`