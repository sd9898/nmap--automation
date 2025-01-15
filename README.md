# Nmap Automation Project

This project automates the process of port scanning using Nmap. It provides a structured way to perform various types of scans, parse the results, and generate reports.

## Setup

1. **Install Nmap**: Ensure that Nmap is installed on your system. You can download it from [Nmap's official website](https://nmap.org/download.html).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/sd9898/nmap-automation.git
   cd nmap-automation
   ```

3. **Install Dependencies**: Make sure you have Python installed. Then, install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To perform a scan, run the `scanner.py` script with the target IP address or hostname:
```bash
python src/scanner.py <target> [--timestamp <timestamp>]
```

### Scan Types

- **SYN Scan** (`-sS`): This is a stealthy scan that sends SYN packets to determine open ports.
- **TCP Connect Scan** (`-sT`): This scan attempts to establish a full TCP connection.
- **UDP Scan** (`-sU`): This scan checks for open UDP ports.

## Results

Scan results will be saved in the `results` directory in both JSON and XML formats. You can generate an HTML report from the scan results.

### Running Tests

To run the tests, use the following command:
```bash
python -m unittest discover -s tests
```

### License

This project is licensed under the MIT License.
