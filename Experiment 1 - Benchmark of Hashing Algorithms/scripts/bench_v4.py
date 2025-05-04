import os
import hashlib
import psutil
import time
import csv
import json
from datetime import datetime
import subprocess
import multiprocessing

def get_system_info():
    info = {
        "processor": psutil.cpu_freq().max,
        "ram": psutil.virtual_memory().total,
        "os": psutil.os.uname().sysname
    }
    return info

def get_cpu_usage():
    cpu_usage = {
        "core0": psutil.cpu_percent(percpu=True)[0],
        "core1": psutil.cpu_percent(percpu=True)[1],
        "core2": psutil.cpu_percent(percpu=True)[2],
        "core3": psutil.cpu_percent(percpu=True)[3]
    }
    return cpu_usage

def get_memory_usage():
    memory = psutil.virtual_memory()
    memory_usage = {
        "used": memory.used,
        "free": memory.available
    }
    return memory_usage

def get_disk_io():
    disk_io = psutil.disk_io_counters()
    disk_usage = {
        "read": disk_io.read_bytes,
        "write": disk_io.write_bytes
    }
    return disk_usage

def get_temperature_and_voltages():
    temperature_and_voltages = {}
    try:
        cpu_temp_output = subprocess.check_output(["vcgencmd", "measure_temp"]).decode("utf-8")
        cpu_temp = float(cpu_temp_output.split("=")[1].split("'")[0])

        core_volt_output = subprocess.check_output(["vcgencmd", "measure_volts", "core"]).decode("utf-8")
        core_volt = float(core_volt_output.split("=")[1].split("V")[0])

        sdram_c_volt_output = subprocess.check_output(["vcgencmd", "measure_volts", "sdram_c"]).decode("utf-8")
        sdram_c_volt = float(sdram_c_volt_output.split("=")[1].split("V")[0])

        sdram_i_volt_output = subprocess.check_output(["vcgencmd", "measure_volts", "sdram_i"]).decode("utf-8")
        sdram_i_volt = float(sdram_i_volt_output.split("=")[1].split("V")[0])

        sdram_p_volt_output = subprocess.check_output(["vcgencmd", "measure_volts", "sdram_p"]).decode("utf-8")
        sdram_p_volt = float(sdram_p_volt_output.split("=")[1].split("V")[0])

        temperature_and_voltages = {
            "cpu_temp": cpu_temp,
            "core_volt": core_volt,
            "sdram_c_volt": sdram_c_volt,
            "sdram_i_volt": sdram_i_volt,
            "sdram_p_volt": sdram_p_volt
        }
    except subprocess.CalledProcessError:
        temperature_and_voltages = {
            "cpu_temp": None,
            "core_volt": None,
            "sdram_c_volt": None,
            "sdram_i_volt": None,
            "sdram_p_volt": None
        }
    return temperature_and_voltages

def hash_file(file_path, hash_algorithm, chunk_size, record_data):
    if hash_algorithm == "md5":
        hasher = hashlib.md5()
    elif hash_algorithm == "sha3_256":
        hasher = hashlib.sha3_256()
    elif hash_algorithm == "sha256":
        hasher = hashlib.sha256()
    else:
        raise ValueError("Invalid hash algorithm")

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            hasher.update(chunk)
            record_data("during")  # Call the record_data function directly

    return hasher.hexdigest()

def process_file(file_path, hash_algorithm, chunk_size, output_folder):
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # Convert to MB
    file_type = os.path.splitext(file_name)[1]

    print(f"Running {hash_algorithm} on {file_name} with chunk size {chunk_size}")

    csv_file = f"{output_folder}/{file_name}_{hash_algorithm}.csv"
    json_file = f"{output_folder}/{file_name}_{hash_algorithm}.json"

    csv_file_exists = os.path.exists(csv_file)
    json_file_exists = os.path.exists(json_file)

    with open(csv_file, "a", newline="") as csvfile, open(json_file, "a") as jsonfile:
        fieldnames = ["timestamp", "event", "chunk_size", "file_name", "file_size", "file_type", "hash_algorithm", "duration",
                      "system_info", "cpu_usage_core0", "cpu_usage_core1", "cpu_usage_core2", "cpu_usage_core3",
                      "memory_usage", "disk_io", "cpu_temp", "core_volt", "sdram_c_volt", "sdram_i_volt", "sdram_p_volt"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not csv_file_exists:
            writer.writeheader()

        results = []

        def record_data(event, duration=None):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Include milliseconds
            system_info = get_system_info()
            cpu_usage = get_cpu_usage()
            memory_usage = get_memory_usage()
            disk_io = get_disk_io()
            temperature_and_voltages = get_temperature_and_voltages()

            result = {
                "timestamp": timestamp,
                "event": event,
                "chunk_size": chunk_size,
                "file_name": file_name,
                "file_size": file_size,
                "file_type": file_type,
                "hash_algorithm": hash_algorithm,
                "duration": duration if event == "during" else "",
                "system_info": system_info,
                "cpu_usage_core0": cpu_usage["core0"],
                "cpu_usage_core1": cpu_usage["core1"],
                "cpu_usage_core2": cpu_usage["core2"],
                "cpu_usage_core3": cpu_usage["core3"],
                "memory_usage": memory_usage,
                "disk_io": disk_io,
                "cpu_temp": temperature_and_voltages["cpu_temp"],
                "core_volt": temperature_and_voltages["core_volt"],
                "sdram_c_volt": temperature_and_voltages["sdram_c_volt"],
                "sdram_i_volt": temperature_and_voltages["sdram_i_volt"],
                "sdram_p_volt": temperature_and_voltages["sdram_p_volt"]
            }
            writer.writerow(result)
            results.append(result)

        # Record data before hashing
        start_time = time.time()
        end_time = start_time + 3

        while time.time() < end_time:
            record_data("before")

        # Record data during hashing
        start_time = time.time()
        hash_value = hash_file(file_path, hash_algorithm, chunk_size, record_data)  # Corrected call
        end_time = time.time()
        duration = end_time - start_time

        record_data("during", duration)

        # Record data after hashing
        start_time = time.time()
        end_time = start_time + 3

        while time.time() < end_time:
            record_data("after")

        # Save the results to JSON file
        if not json_file_exists:
            json.dump(results, jsonfile, indent=2)
        else:
            jsonfile.write(",\n")
            json.dump(results, jsonfile, indent=2)

def benchmark_hashing(image_folder, output_folder, chunk_sizes):
    hash_algorithms = ["md5", "sha3_256", "sha256"]

    for hash_algorithm in hash_algorithms:
        for chunk_size in chunk_sizes:
            print(f"Running {hash_algorithm} with chunk size {chunk_size}")

            for file_name in os.listdir(image_folder):
                file_path = os.path.join(image_folder, file_name)
                
                processes = []
                process = multiprocessing.Process(target=process_file, args=(file_path, hash_algorithm, chunk_size, output_folder))
                processes.append(process)
                process.start()

                for process in processes:
                    process.join()

def calculate_total_time(image_folder, output_folder, chunk_sizes):
    hash_algorithms = ["md5", "sha3_256", "sha256"]
    total_times = {}

    for hash_algorithm in hash_algorithms:
        total_times[hash_algorithm] = {}
        for chunk_size in chunk_sizes:
            total_times[hash_algorithm][chunk_size] = 0

            for file_name in os.listdir(image_folder):
                csv_file = f"{output_folder}/{file_name}_{hash_algorithm}.csv"
                if os.path.exists(csv_file):
                    with open(csv_file, "r") as csvfile:
                        reader = csv.DictReader(csvfile)
                        for row in reader:
                            if row["event"] == "during":
                                duration = row["duration"]
                                if duration:
                                    total_times[hash_algorithm][chunk_size] += float(duration)
                else:
                    print(f"CSV file not found: {csv_file}")

    # Print total times for each algorithm and chunk size
    print("\nTotal Hashing Times:")
    for hash_algorithm in hash_algorithms:
        print(f"\n{hash_algorithm}:")
        for chunk_size in chunk_sizes:
            print(f"Chunk Size {chunk_size}: {total_times[hash_algorithm][chunk_size]:.2f} seconds")

def find_lowest_total_time(image_folder, output_folder):
    hash_algorithms = ["md5", "sha3_256", "sha256"]
    chunk_sizes = [4096, 8192, 16384]

    print("\nLowest Total Time per Image:")
    for file_name in os.listdir(image_folder):
        lowest_time = float("inf")
        lowest_combo = None
        for hash_algorithm in hash_algorithms:
            for chunk_size in chunk_sizes:
                csv_file = f"{output_folder}/{file_name}_{hash_algorithm}.csv"
                if os.path.exists(csv_file):
                    with open(csv_file, "r") as csvfile:
                        reader = csv.DictReader(csvfile)
                        total_time = 0
                        for row in reader:
                            if row["event"] == "during":
                                duration = row["duration"]
                                if duration:
                                    total_time += float(duration)
                        if total_time < lowest_time:
                            lowest_time = total_time
                            lowest_combo = (hash_algorithm, chunk_size)
                else:
                    print(f"CSV file not found: {csv_file}")
        print(f"{file_name}: {lowest_combo[0]} with chunk size {lowest_combo[1]} ({lowest_time:.2f} seconds)")

# Configuration
image_folder = "/media/usb/captures"
output_folder = "/media/usb/results"
chunk_sizes = [4096, 8192, 16384]  # Suggested chunk sizes

# Run benchmarking
benchmark_hashing(image_folder, output_folder, chunk_sizes)

# Calculate total hashing times
calculate_total_time(image_folder, output_folder, chunk_sizes)

# Find the lowest total time for each image
find_lowest_total_time(image_folder, output_folder)
