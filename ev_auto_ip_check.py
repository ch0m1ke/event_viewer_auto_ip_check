"""
Event Viewer Auto IP check v1.0.3

This script takes in input a csv file generated by Event Viewer in Cisco Security Manager
and returns a list the most active IPs detected and blocked by the firewall (up to five).
List and description are copied to the clipboard.

Michele Chiarello - michele[dot]chiarello[at]gmail[dot]com
"""

import os
import sys
import platform
import subprocess
import csv

def save_ip(ip_details:list , count: int, dest_list: list) -> bool:
    if(ip_details == [] or count <= 0):
        return False
    current_ip_index = -1
    for item in dest_list:
        if ip_details[1] in item[1]: #  Check if ip is present in dest_list and update if so
            current_ip_index = dest_list.index(item)
            break
    if current_ip_index != -1: # If ip not found in list
        dest_list[current_ip_index][-1]+=count
    else:
        ip_details.append(count)
        dest_list.append(ip_details)
    return True

def copy_to_clipboard(data_to_copy: str) -> bool:
    this_os = platform.system()
    if this_os == "Windows":
        subprocess.run(['clip.exe'], input=data_to_copy.strip().encode('utf-8'), check=True)
    elif this_os == "Linux": # To test
        with subprocess.Popen(['xclip','-selection','data_to_copy'], stdin=subprocess.PIPE) as proc:
            proc.stdin.write(data_to_copy)
            proc.stdin.close()
            proc.wait() # retcode = proc.wait()
    elif this_os == "Darwin":
        with subprocess.Popen('pbcopy', env={'LANG': 'en_US.UTF-8'}, stdin=subprocess.PIPE) as process:
            process.communicate(data_to_copy.encode('utf-8'))
    else:
        return False
    return True

def color_print(text: str, color: str) -> bool:
    font_colors = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "terminator": "\033[0m"
    }
    if color not in font_colors:
        return False
    this_os = platform.system()
    if this_os == "Windows":
        os.system('color')
    print(f"{font_colors[color]}{text}{font_colors['terminator']}")
    return True

    
if len(sys.argv) < 2:
    file_name = input("File name: ")
else:
    file_name = sys.argv[1]
# Open file and check entries
try:
    with open(file_name, mode='r', encoding='utf_8', newline='') as csvfile:
        csv_header = [
            'Receive Time',
            'Severity',
            'Event Type ID',
            'Event Name',
            'Device',
            'Source',
            'Source User Identity',
            'Source Service',
            'Destination Service',
            'Destination',
            'Destination FQDN',
            'Action',
            'Risk Rating',
            'Description',
            'Event ID',
            'Source Interface',
            'Destination Interface'
        ]
        ip_list = []
        fw_check = csv.reader(csvfile, delimiter=',')
        try:
            if next(fw_check) == csv_header: # Check if file contains the right header
                counter = 0
                current_ip = ''
                ip_info = []
                for row in fw_check:
                    if len(row) != len(csv_header) and row != []: # line doesn't match header
                        color_print("\n[ERROR] The file may be corrupted!", "red")
                        sys.exit()
                    if len(row)!=0:
                        if current_ip == '':
                            current_ip = row[5]
                            ip_info.append(row[0]) # Date of Event
                            ip_info.append(row[5]) # Source IP
                            ip_info.append(row[7]) # Source port
                            ip_info.append(row[9]) # Destination IP
                            ip_info.append(row[8]) # Destination port
                        if row[5] == current_ip:
                            counter+=1
                        else:
                            save_ip(ip_info[:], counter, ip_list)
                            current_ip = row[5]
                            ip_info[0] = row[0] # Date of Event
                            ip_info[1] = row[5] # Source IP
                            ip_info[2] = row[7] # Source port
                            ip_info[3] = row[9] # Destination IP
                            ip_info[4] = row[8] # Destination port
                            counter = 1
                save_ip(ip_info[:], counter, ip_list)
                list_end = len(ip_list)
                if len(ip_list)>4:
                    list_end = 5 # Used to get the first 5 IPs
                if len(ip_list)>0:
                    ip_list.sort(key=lambda row: (row[-1]), reverse=True)
                    clipboard = "These are the suspicious IPs that need to be verified on the external/internal router:\n\nShort situation regarding the source ip`s matching the search:\n"
                    for entry in range(0,list_end):
                        clipboard+=(f"\nSource IP: {ip_list[entry][1]} is seen {ip_list[entry][-1]} times in file uploaded!")
                    for entry in range(0,list_end):
                        clipboard+=(f"\n\nDate of Event: {ip_list[entry][0]}\n")
                        clipboard+=(f"Source IP: {ip_list[entry][1]}\n")
                        clipboard+=(f"Source port: {ip_list[entry][2]}\n")
                        clipboard+=(f"Destination IP: {ip_list[entry][3]}\n")
                        clipboard+=(f"Destination port: {ip_list[entry][4]}")
                    copy_to_clipboard(clipboard)
                    color_print(f"\n{clipboard}", "green")
                    color_print("\nText copied to clipboard, lazy b*****d!", "yellow")
                else:
                    color_print("\n[ERROR] No records found!", "red")
            else:
                color_print("\n[ERROR] The file may be corrupted!", "red")
        except StopIteration:
            color_print("\n[ERROR] The file is empty or corrupted!", "red")
except OSError as err:
    color_print("\n[ERROR] The file does't exist or can't be opened!", "red")
input("\nPress ENTER to quit...")
