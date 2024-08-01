#!/bin/bash

# Extract the package
tar -xzvf kserver_package.tar.gz

# Move the binary to /usr/local/bin
cp kserver_package/kserver /usr/local/bin/
cp kserver_package/webdis.json /usr/local/bin/

# Move the systemd service file
cp kserver_package/kserver.service /etc/systemd/system/

# Reload systemd and enable the service
systemctl daemon-reload
# systemctl enable my_service
systemctl start kserver
