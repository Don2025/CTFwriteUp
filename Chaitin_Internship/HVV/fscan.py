import subprocess
from concurrent.futures import ThreadPoolExecutor

def run_fscan(ip):
    command = f'fscan -h {ip} -nobr -nopoc'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    output_file = f'Output/{ip}.log'
    with open(output_file, 'w+') as log_file:
        if process.returncode == 0:
            print(f'Successfully scanned IP: {ip}\nOutput: {output.decode()}\n')
            log_file.write(f'Successfully scanned IP: {ip}\nOutput: {output.decode()}\n')
        else:
            print(f'Error scanning IP: {ip}\nError Message: {error.decode()}\n')
            log_file.write(f'Error scanning IP: {ip}\nError Message: {error.decode()}\n')


if __name__ == '__main__':
    with open('ip.txt', 'r') as file:
        ips = file.readlines()

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(run_fscan, [ip.strip() for ip in ips])

    print("All scans completed. Check the logfile in folder Output")