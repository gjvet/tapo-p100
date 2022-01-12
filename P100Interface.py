import utils.TapoPlug as tapo
import pprint
import sys
import time

def readConfig() -> tuple[str,str,str]:
    with open("config") as file:
        config = file.read()
    elements = config.splitlines()
    ip = elements[0]
    email = elements[1]
    password = elements[2]
    return ip, email, password

def connect() -> tapo.P100:
    ip, email, password = readConfig()
    plug = tapo.P100(ip,email,password)
    plug.handshake()
    plug.login()
    return plug

def status(plug:tapo.P100):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(plug.getDeviceInfo())
    code = plug.getDeviceInfo().get("error_code")
    meaning = plug.errorCodes.get(str(code))
    print(f"Error Code {code}: {meaning}")

def timer(plug:tapo.P100,minutes:int):
    plug.turnOn()
    time.sleep(minutes*60)
    plug.turnOff()

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
    elif (sys.argv[1] == "status"):
        status(plug)
    elif (sys.argv[1] == "name"):
        print(f"Device Name: {plug.getDeviceName()}")
    elif (sys.argv[1] == "timer" and len(sys.argv) > 2):
        timer(plug,int(sys.argv[2]))
    else:
        help()
