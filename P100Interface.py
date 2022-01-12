import utils.TapoPlug as tapo
import pprint
import configparser
import sys
import time

# Reads the config.ini file to get IP, email and password 
def readConfig() -> tuple[str,str,str]:
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config["DEFAULT"]["IP"], config["DEFAULT"]["EMAIL"], config["DEFAULT"]["PASSWORD"]

# Authenticates with the plug to allow us to control it
def connect() -> tapo.P100:
    ip, email, password = readConfig()
    plug = tapo.P100(ip,email,password)
    plug.handshake()
    plug.login()
    return plug

# Displays info about the plug
def info(plug:tapo.P100):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(plug.getDeviceInfo())
    code = plug.getDeviceInfo().get("error_code")
    meaning = plug.errorCodes.get(str(code))
    print(f"Error Code {code}: {meaning}")

# An experimental timer function that turns the plug off after a specified time
def timer(plug:tapo.P100,minutes:int):
    plug.turnOn()
    time.sleep(minutes*60)
    plug.turnOff()

# Displays the help message explaining each argument
def help():
    with open("docs/P100Interface.txt") as f:
        instructions = f.read()
        print(instructions)

if (__name__ == "__main__"):
    if (len(sys.argv) < 2):
        help()
        exit(1)
    plug = connect()
    if (sys.argv[1] == "on"):
        plug.turnOn()
        print(f"{plug.getDeviceName()}: ON")
    elif (sys.argv[1] == "off"):
        plug.turnOff()
        print(f"{plug.getDeviceName()}: OFF")
    elif (sys.argv[1] == "info"):
        info(plug)
    elif (sys.argv[1] == "name"):
        print(f"Device Name: {plug.getDeviceName()}")
    elif (sys.argv[1] == "timer" and len(sys.argv) > 2):
        timer(plug,int(sys.argv[2]))
    else:
        help()
