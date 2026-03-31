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

#!/usr/bin/env python3
import pwd
import grp
import os
import subprocess
from datetime import datetime

def test_empty_password(username):
    """Test if user has empty password"""
    try:
        process = subprocess.Popen(
            ['su', username, '-c', 'exit'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        outs, errs = process.communicate(input=b'\n', timeout=1)
        if process.returncode == 0:
            return True, "Empty password"
        return False, "Password is set"
    except:
        return False, "Test failed"

def test_username_password(username):
    """Test if password equals username"""
    try:
        process = subprocess.Popen(
            ['su', username, '-c', 'exit'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        outs, errs = process.communicate(input=f"{username}\n".encode(), timeout=1)
        if process.returncode == 0:
            return True, "Password = Username"
        return False, "Password != Username"
    except:
        return False, "Test failed"

def perform_basic_audit():
    """Perform basic security checks on all users"""
    print("\n=== Basic Security Checks ===")
    print("Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("-" * 90)
    print("USERNAME      UID    SHELL         GROUPS         EMPTY_PWD  USER=PWD   STATUS")
    print("-" * 90)
    
    secure_users = []
    vulnerable_users = []
    
    with open('/etc/passwd', 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 7:
                username = parts[0]
                uid = int(parts[2])
                shell = os.path.basename(parts[6])
                
                # Skip non-login shells
                if shell.endswith('false') or shell.endswith('nologin'):
                    continue
                
                # Get groups
                groups = []
                try:
                    for group in grp.getgrall():
                        if username in group.gr_mem:
                            groups.append(group.gr_name)
                except:
                    groups = ["Error"]
                
                groups_str = ','.join(groups)
                if len(groups_str) > 12:
                    groups_str = groups_str[:9] + "..."
                
                # Basic security checks
                empty_pwd, _ = test_empty_password(username)
                weak_pwd, _ = test_username_password(username)
                
                # Determine status
                if empty_pwd:
                    status = "VULNERABLE (Empty pwd)"
                    vulnerable_users.append(username)
                elif weak_pwd:
                    status = "VULNERABLE (User=Pwd)"
                    vulnerable_users.append(username)
                else:
                    status = "SECURE"
                    secure_users.append((username, uid, shell))
                
                # Print results
                print(f"{username:<12} {uid:<6} {shell:<13} {groups_str:<13} ", end='')
                print(f"{'Yes' if empty_pwd else 'No':<10} {'Yes' if weak_pwd else 'No':<9} {status}")
    
    # Print summary
    print("\n=== Basic Audit Summary ===")
    print(f"Total users checked: {len(secure_users) + len(vulnerable_users)}")
    print(f"Vulnerable users: {len(vulnerable_users)}")
    print(f"Secure users: {len(secure_users)}")
    
    if vulnerable_users:
        print("\nVulnerable users found:")
        for user in vulnerable_users:
            print(f"- {user}")

def main():
    if os.geteuid() == 0:
        print("WARNING: This script should not be run as root!")
        exit(1)
    
    try:
        perform_basic_audit()
    except KeyboardInterrupt:
        print("\nAudit interrupted by user")
    except Exception as e:
        print(f"Error during audit: {str(e)}")

if __name__ == "__main__":
    main()
