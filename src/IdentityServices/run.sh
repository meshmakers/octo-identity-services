#!/bin/sh

if [ -d "/var/oem" ]; then
    echo "Copy oem files..."
    cp -R -L /var/oem /app/wwwroot/oem
fi

echo "Start Identity Services"
dotnet Meshmakers.Octo.Backend.IdentityServices.dll