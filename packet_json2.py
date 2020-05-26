import subprocess

command = "tshark -i 2 -f \"tcp or udp\" -T json"
try:
    output = subprocess.check_output(command, shell=True, stdout=subprocess.PIPE)
except subprocess.CalledProcessError as e:
    print("An error has been occured", e)
    raise

print("The subprocess output:", output)