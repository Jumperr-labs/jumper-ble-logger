# Test for root
if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root (sudo).  Aborting." >&2
  exit 1
fi

OS="debian"

if [ -f /etc/lsb-release ]; then
    OS=$(awk '/DISTRIB_ID=/' /etc/*-release | sed 's/DISTRIB_ID=//' | tr '[:upper:]' '[:lower:]')
fi

if [ "$(pidof systemd)" != '' ]; then
    init_ststem='systemd'
elif [ "$(pidof /sbin/init)" != '' ]; then
    init_system='init'
else
    echo "Could not detect neither systemd or init.  Aborting" >&2
    exit 1
fi

INSTALLATION_LOG=/tmp/jumper_ble_logger_installation.log
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DEST_DIR=/etc/jumper_ble_logger
FIFO_DIR=/var/run/jumper_ble_logger
SERVICE_USER=jumperble
SERVICE_NAME=jumper-ble
CONFIG_DIR=/etc/jumper_logging_agent
CONFIG_FILE=config.json

if id -u ${SERVICE_USER} >/dev/null 2>&1; then
    echo Reusing user ${SERVICE_USER}
else
    useradd ${SERVICE_USER} -M -s /usr/sbin/nologin -c "Jumper BLE Logger"
    usermod -aG sudo ${SERVICE_USER}
fi

echo Creating directories...
#rm -rf ${DEST_DIR}
if [!-d ${DEST_DIR}]; then
    mkdir -p ${DEST_DIR}
fi;
if [!-d ${FIFO_DIR}]; then
    mkdir -p ${FIFO_DIR}
fi;

if [ ! -d ${CONFIG_DIR} ]; then
  mkdir -p ${CONFIG_DIR}
  cp ${CONFIG_FILE} ${CONFIG_DIR}
fi

chown ${SERVICE_USER}:${SERVICE_USER} ${FIFO_DIR}

echo Copying files...
# Copying the agent to its final destination
COPY_FILES="events_config.json"
for FILE in ${COPY_FILES}; do
    cp -R ${SCRIPT_DIR}/${FILE} ${DEST_DIR}/
done

chown -R ${SERVICE_USER}:${SERVICE_USER} ${DEST_DIR}
chmod -R u+rw,g+rw ${DEST_DIR}

# Setup the jumper agent service
echo Setting up service ${SERVICE_NAME}...

if [ $init_system = "init" ]; then
    SERVICE_FILE=/etc/init.d/${SERVICE_NAME}

    cp ${SCRIPT_DIR}/jumperbleinitd.template ${SERVICE_FILE}

    chmod 755 ${SERVICE_FILE}

    # Start the jumper agent service
    update-rc.d ${SERVICE_NAME} defaults
    update-rc.d ${SERVICE_NAME} enable
#    service ${SERVICE_NAME} start

    sleep 1

    if [[ "`service ${SERVICE_NAME} status`" -ne "Running" ]]; then
        echo "Error: Service ${SERVICE_NAME} is not running. Status information: " >&2
        exit 1
    fi
else
    SERVICE_FILE=/lib/systemd/${SERVICE_NAME}.service

    cp ${SCRIPT_DIR}/jumperble.template ${SERVICE_FILE}
    echo "ExecStart=/usr/local/bin/jumper-ble-logger -v" >> ${SERVICE_FILE}
    echo "User=root" >> ${SERVICE_FILE}
    ln -fs ${SERVICE_FILE} /etc/systemd/system/${SERVICE_NAME}.service

    # Start the jumper agent service
    systemctl daemon-reload
    #systemctl start jumper-ble.service

    sleep 1

    if [[ "`systemctl is-active ${SERVICE_NAME}`" -ne "active" ]]; then
        echo "Error: Service ${SERVICE_NAME} is not running. Status information: " >&2
        echo "" >&2
        systemctl status ${SERVICE_NAME} >&2
        exit 1
    fi
fi


echo Success! Jumper logging agent is now installed and running.
