#!/bin/bash

# TPM configuration
TCTI_OPTION="-Tspi-ltt2go"
AUTH="N3v3rend"

# Function to check if a command was successful
check_status() {
    if [ $? -ne 0 ]; then
        echo "Error: $1" >&2
        exit 1
    fi
}

# Clear persistent keys
clear_persistent_keys() {
    echo "Warning: This will clear all persistent keys in the TPM."
    echo "This action cannot be undone and may affect other applications using the TPM."
    read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        echo "Clearing persistent keys..."
        # Get list of persistent handles
        handles=$(tpm2_getcap handles-persistent $TCTI_OPTION | cut -d ' ' -f 2)
        
        # Evict each persistent handle
        for handle in $handles; do
            echo "Evicting handle: $handle"
            tpm2_evictcontrol -P "$AUTH" -C o -c $handle $TCTI_OPTION
            check_status "Failed to evict handle $handle"
        done
        
        echo "All persistent keys have been cleared."
    else
        echo "Operation cancelled."
    fi
}

# Run the function to clear persistent keys
clear_persistent_keys
