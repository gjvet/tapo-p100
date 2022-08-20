# Tapo P100 Controller

A collection of Python scripts for controlling a Tapo P100 smart plug. A lot of the backend is modified code from this [repo](https://github.com/fishbigger/TapoP100). The main way to interact with these libraries is to run the `P100Interface.py` file with any of the supported command line options:

```
Command Line Tool for Controlling a Tapo P100 Plug

Options:
    on: turn the plug on
    off: turn the plug off
    info: get information about the current state of the plug
    name: get the name of the plug
    timer [minutes]: turn the plug on for the specified number of minutes
    help: display this message
```

The above message can be displayed by running the file with no arguments or the `help` argument.

## First Use

Before running the `P100Interface.py` script, modify the `config.ini` file to contain the IP of the smart plug and email address and password for the account associated with the device:

```ini
[DEFAULT]
IP = 192.168.0.100
EMAIL = example@email.com
PASSWORD = top_secret
```

## Dependencies

```bash
python3 -m pip install pycryptodome pkcs7
```

