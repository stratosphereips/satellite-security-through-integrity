#!/bin/bash

# Define the payload path
PAYLOAD_PATH="/home/test/Documents/Exp2/payload"

# Print start message
echo "Starting security configuration for $PAYLOAD_PATH..."

# 1. Ensure the payload directory exists
echo "Creating payload directory..."
sudo mkdir -p $PAYLOAD_PATH

# 2. Set ownership and permissions
echo "Setting base ownership and permissions..."
sudo chown camera:camera $PAYLOAD_PATH
sudo chmod 750 $PAYLOAD_PATH

# 3. Install required packages
echo "Installing required packages..."
sudo apt-get update
sudo apt-get install -y acl auditd audispd-plugins

# 4. Enable and start audit service
echo "Enabling audit service..."
sudo systemctl enable auditd
sudo systemctl start auditd

# 5. Set base permissions and ACLs for payload directory
echo "Configuring ACLs..."
# Remove all existing ACLs
sudo setfacl -b $PAYLOAD_PATH

# Set default ACLs for new files/directories
sudo setfacl -R -dm u::rwx,g::rx,o::- $PAYLOAD_PATH
sudo setfacl -R -m u::rwx,g::rx,o::- $PAYLOAD_PATH

# 6. Add specific user/group permissions
echo "Setting up camera user permissions..."
# Give camera user full access
sudo setfacl -R -m u:camera:rwx $PAYLOAD_PATH
sudo setfacl -d -m u:camera:rwx $PAYLOAD_PATH

# 7. Give parent directory traversal permissions
echo "Setting up directory traversal permissions..."
# This is crucial for accessing nested directories
sudo setfacl -m u:camera:x /home
sudo setfacl -m u:camera:x /home/test
sudo setfacl -m u:camera:x /home/test/Documents
sudo setfacl -m u:camera:x /home/test/Documents/Exp2

# 8. Set up audit monitoring
echo "Setting up audit monitoring..."
# Clear any existing audit rules
sudo auditctl -D

# Add audit rule with key for the payload directory
sudo auditctl -w $PAYLOAD_PATH -p warx -k payload_access

# 9. Verify configurations
echo -e "\nVerifying configurations:"
echo -e "\nCurrent ACL permissions:"
getfacl $PAYLOAD_PATH

echo -e "\nCurrent audit rules:"
sudo auditctl -l

# 10. Test audit logging with camera user
echo -e "\nTesting audit logging as camera user..."
sudo -u camera bash -c "
    echo 'Testing file creation...'
    touch $PAYLOAD_PATH/test.txt
    echo 'Testing file writing...'
    echo 'test content' > $PAYLOAD_PATH/test.txt
    echo 'Testing file reading...'
    cat $PAYLOAD_PATH/test.txt
    echo 'Testing file deletion...'
    rm $PAYLOAD_PATH/test.txt
"

echo "Wait a few seconds for audit to process..."
sleep 5

echo -e "\nRecent audit events:"
sudo ausearch -f $PAYLOAD_PATH -ts recent

echo -e "\nSetup complete! To monitor access, use:"
echo "sudo ausearch -k payload_access    # For all access events"
echo "sudo ausearch -k payload_access -ts recent    # For recent events"
echo "sudo ausearch -f $PAYLOAD_PATH    # For specific path events"

# Optional: Add examples of monitoring specific operations
echo -e "\nExamples of specific monitoring:"
echo "1. Monitor write operations:"
echo "   sudo ausearch -k payload_access -sc write"
echo "2. Monitor access by camera user:"
echo "   sudo ausearch -k payload_access -ua camera"
echo "3. Monitor failed access attempts:"
echo "   sudo ausearch -k payload_access -sv no"
