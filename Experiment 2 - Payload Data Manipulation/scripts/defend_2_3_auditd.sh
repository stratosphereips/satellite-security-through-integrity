# Copyright (C) 2024-2026 Juani Bousquet
# Repository: https://github.com/stratosphereips/satellite-security-through-integrity
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# ADDITIONAL RESTRICTION (per GPL v2 Section 7):
# This software may not be used, in whole or in part, for commercial purposes
# without prior written permission from the copyright holder.
# Commercial use includes, but is not limited to, use in a commercial product,
# use in a service offered for a fee, or use by a for-profit organization.
# For commercial licensing inquiries, contact: juanibuqt@gmail.com
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>

#!/bin/bash

# Define paths
PAYLOAD_PATH="/home/test/Documents/Exp2/payload"
AUDIT_RULES="/etc/audit/rules.d/audit.rules"
AUDITD_CONF="/etc/audit/auditd.conf"

# Install required packages
echo "Installing audit packages..."
sudo apt-get update
sudo apt-get install -y auditd audispd-plugins

# Configure auditd with updated options
echo "Configuring auditd..."
sudo cat << EOF | sudo tee $AUDITD_CONF
#
# This file controls the configuration of the audit daemon
#

# Location where audit logs are stored
log_file = /var/log/audit/audit.log

# Format of log entries: RAW for maximum information
log_format = RAW

# Group that owns the log files
log_group = adm

# Nice value added to auditd. Higher number = higher priority
priority_boost = 4

# How to write to the disk: INCREMENTAL_ASYNC is best for performance
flush = INCREMENTAL_ASYNC

# How many records to write before issuing an explicit flush (50 is default)
freq = 50

# Number of log files to keep if rotate is given as max_log_file_action
num_logs = 5

# How computer node names are inserted: NONE, HOSTNAME, FQD, or USER
name_format = NONE

# Maximum file size in megabytes. When reached, trigger max_log_file_action
max_log_file = 8

# What action to take when max_log_file is reached: ROTATE to keep old logs
max_log_file_action = ROTATE

# Space left in megabytes at which we begin alerting
space_left = 75

# What action to take when space_left is reached: SYSLOG to alert admin
space_left_action = SYSLOG

# Send email when space_left alert occurs
verify_email = yes

# Email address for space_left alerts
action_mail_acct = root

# Space left in megabytes at which we take admin_space_left_action
admin_space_left = 50

# Action when admin_space_left is reached: SUSPEND stops logging
admin_space_left_action = SUSPEND

# Action to take when disk is full: SUSPEND stops logging
disk_full_action = SUSPEND

# Action to take on disk error: SUSPEND stops logging to prevent corruption
disk_error_action = SUSPEND

# Use TCP wrappers to control remote access
use_libwrap = yes

# Number of pending connections allowed
tcp_listen_queue = 5

# Maximum number of connections from the same IP address
tcp_max_per_addr = 1

# Number of seconds a client can be idle before being disconnected
tcp_client_max_idle = 0

# Whether to use Kerberos 5 for authentication
enable_krb5 = no

# Principal name for Kerberos (only used if enable_krb5=yes)
krb5_principal = auditd

# Whether to distribute audit events across network (cluster environments)
distribute_network = no
EOF

# Set up audit rules
echo "Setting up audit rules..."
sudo cat << EOF | sudo tee $AUDIT_RULES
# Delete all previous rules
-D

# Set buffer size
-b 8192

# Monitor payload directory
-w $PAYLOAD_PATH -p warx -k payload_access

# Monitor access to audit configuration
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

# Monitor system administration activities
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity

# Monitor sudo usage
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
EOF

# Set proper permissions
sudo chmod 750 /etc/audit/rules.d/
sudo chmod 640 $AUDIT_RULES

# Restart auditd to apply changes
echo "Restarting audit daemon..."
sudo service auditd restart

# Verify rules are loaded
echo "Verifying audit rules..."
sudo auditctl -l

echo "Testing audit logging..."
# Create a test file as camera user
sudo -u camera touch $PAYLOAD_PATH/test.txt
sudo -u camera rm $PAYLOAD_PATH/test.txt

echo "Waiting for audit events to be processed..."
sleep 5

echo "Recent audit events for payload access:"
sudo ausearch -k payload_access -ts recent
