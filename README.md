# Satellite Security Through Integrity

Master's thesis repository for implementing satellite data and image captures integrity against malicious threats.

## Abstract

Small satellites face significant challenges in guaranteeing the integrity of satellite and payload data in orbit. In scenarios of malicious software running in the satellite, minimal mechanisms are in place to protect satellite data or give status visibility to mission control, especially in low-cost open-hardware satellites like CubeSats and SmallSats.

This thesis explores how to improve the data integrity of satellite data, packets, and image captures sent to the ground station. It studies how to maintain and guarantee integrity against threats or attacks on the satellite and captured images.

The proposal is to use a hardware TPM (Trusted Platform Module), secure implementations of hash and sign algorithms, and a hash chain with proof of work (PoW) to maintain a verifiable and immutable record of operations on satellite and payload data. The TPM (Trusted Platform Module) is also used to guarantee the integrity and traceability of image captures to a specific satellite.

## Experiments

### Experiment 1 - Benchmark of Hashing Algorithms
The proposed benchmark evaluation aims to find the less resource-consuming algorithm and chunk size for hashing on the Raspberry Pi. In this scenario, this hardware represents the resource-constrained satellite system. To achieve this goal, the consumption of resources is measured on the Raspberry Pi while performing hashing operations with various algorithms. The benchmark includes CPU consumption (each core, in percentage), memory (free and used in MB), memory card storage (read/write operations in MB/s), and CPU temperature (in Celsius degrees). Additionally, time spent is measured (in seconds) on a Raspberry Pi when doing hashing operations. The hashing algorithms used are MD5, SHA-256, and SHA3-256, with chunk sizes (in bytes) 4096, 8192, and 16384. Tableau graphs and all data collected during benchmarks are available.

### Experiment 2 - Payload Data Manipulation
This experiment simulates a malware attack that modifies the payload files. In this case, the files are the image captures, and the malware tries to extract the target coordinates for later ex-filtration.

### Experiment 3 - Malware Altering Captures
This experiment explores the challenge of having malware on the satellite's main board, a Raspberry Pi ('first domain'), trying to manipulate the satellite payload's image captures. A Trusted Platform Module (TPM) is implemented in a separate domain, Raspberry Pi ('second domain'), together with the satellite's camera, implementing hashing and signature operations to images as soon they are captured, guaranteeing integrity and preventing malware's actions.

### Experiment 4 - Malware Targeting Satellite's Core Files
This experiment simulates malware that gains access to the Main Board ('first domain') and attempts to modify or delete files. The files are now monitored by a Log Box ('second domain'). Previous experiments had a 'second domain' with a TPM together with the camera payload, but this approach was not used in this experiment. The Log Box is a new proposal for implementing a secure hash chain that attempts to guarantee the integrity of the system by verifying the existence and content of files before their transmission to the ground station.

## Repository Contents

- **Experiment Code**: Implementation of all four experiments with code used.
- **Tableau Analysis Files**: Experiment 1 Tableau files for visualization and analytics of benchmark results.
- **TPM Integration Code**: Software for interfacing with the Trusted Platform Module LetsTrust-TPM2Go USB - Infineon Optiga SLB 9672 TPM 2.0 fw 15.23 (EAL4+ & FIPS 140-2)
- **Hash Chain Implementation**: Hash chain as an immutable log with Proof of work, verification, and signature using TPM.
- **Documentation**: Detailed methodology and experiments results and analysis (Thesis document)

## Usage

### Prerequisites
- Raspberry Pi (for hardware simulation) - Raspberry Pi 2 Model B v1.1 (2014) & Raspberry Pi 1 Model B+ v1.2 (2014)
- TPM module compatible with Raspberry Pi - LetsTrust-TPM2Go USB - Infineon Optiga SLB 9672 TPM 2.0 fw 15.23 (EAL4+ & FIPS 140-2)
- Python 3.x
- Libraries and tools used in each experiment

### Running Experiments
Each experiment is contained in its directory with dedicated scripts. 
Please check the thesis document which has all details about how to run the experiments.

## About

This repository was developed and is maintained by Bousquet Juan Ignacio mailto:juanibuqt@gmail.com, at the Stratosphere Laboratory at the Czech Technical University in Prague. 
It contains the implementation and evaluation of security measures for protecting the integrity of satellite data in low-cost, open-hardware satellites.

## License

GNU General Public License (GPL) version 2 (check "License" section)
