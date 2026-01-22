#!/bin/bash
set -e

echo "Installing Mailuminati Guardian..."

# Move binary
sudo mv /home/jimmy/setup/Guardian/mi_guardian/mi_guardian /usr/local/bin/mailuminati-guardian
echo "✓ Binary installed"

# Create config directory
sudo mkdir -p /etc/mailuminati-guardian

# Create config file
sudo tee /etc/mailuminati-guardian/guardian.conf > /dev/null <<'EOF'
# Mailuminati Guardian Configuration
GUARDIAN_BIND_ADDR=127.0.0.1
PORT=12421
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=FTOqQ9Ak0GiXb6t24eBrdY
ORACLE_URL=https://oracle.mailuminati.com
EOF
echo "✓ Config created"

# Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mailuminati 2>/dev/null || true

# Set permissions
sudo chown -R root:mailuminati /etc/mailuminati-guardian
sudo chmod 750 /etc/mailuminati-guardian
sudo chmod 640 /etc/mailuminati-guardian/guardian.conf
echo "✓ Permissions set"

# Create systemd service
sudo tee /etc/systemd/system/mailuminati-guardian.service > /dev/null <<'EOF'
[Unit]
Description=Mailuminati Guardian Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mailuminati-guardian -config /etc/mailuminati-guardian/guardian.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
User=mailuminati

[Install]
WantedBy=multi-user.target
EOF
echo "✓ Systemd service created"

# Start the service
sudo systemctl daemon-reload
sudo systemctl enable --now mailuminati-guardian
echo "✓ Service started"

# Verify
sleep 2
echo ""
echo "Checking status..."
curl -s http://localhost:12421/status | jq 2>/dev/null || curl -s http://localhost:12421/status
echo ""
echo "Installation complete!"
