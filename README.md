# ElDumpo

ElDumpo is a utility that helps reversing linux packed executables

It has two parts:
* dumper
* plugin

The dumper dumps the memory of the packed executable after it unpacked itself in memory  
and generates a .symbols file containing all the symbols available for ELFs in the dump

The plugin loads information from the generated .symbols file and applies it in the disassembler

## Installation

ElDumpo dumper environment  
Put the ElDumpo_dumper anywhere you want on your linux machine

ElDumpo plugin environment  
Put the ElDumpo_plugin in your ida plugins directory
ElDumpo will be added as a plugin in the Edit->Plugins menu

## Usage

Generate a core file and .symbols file
```bash
sudo python3 ElDumpo_dumper.py --pid 1337 # dump by pid
sudo python3 ElDumpo_dumper.py --name top # dump by process name (first one if there are several instances)
sudo python3 ElDumpo_dumper.py --auto --name top # dump by process name and try to download all available debug symbols
```

Put the core file and the .symbols file at the same directory and open in ida

Activate ElDumpo from its menu and it will apply all the information from the generated .symbols file that it could resolve

## Recommendations

ElDumpo can use debug symbols from the ```/usr/lib/debug``` directory, so it is recommended to enable downloading them  

You may enable their download on ubuntu by using the following script:
```bash
printf "deb http://ddebs.ubuntu.com %s main restricted universe multiverse\n" $(lsb_release -cs){,-updates,-proposed} | \
 sudo tee -a /etc/apt/sources.list.d/ddebs.list

sudo apt install ubuntu-dbgsym-keyring
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 428D7C01 C8CAB6595FDFF622

sudo apt update
```
Instructions taken from https://wiki.ubuntu.com/Debug%20Symbol%20Packages

It's recommended to use the ```--auto``` flag to automatically download debug symbols for available packages to help you with reversing

## Requirements

ElDumpo dumper environment
* python3
* Linux, you need to run the file to create the coredump  
Optional
  * Internet connection - if you want to download symbols, you may also take the generated failed symbols list and download it

Tested on ubuntu 20.04

ElDumpo plugin environment
* python3
* IDA 7.7, tested on IDA 7.7 but may work for any IDA that uses the new api

## License
[MIT](https://choosealicense.com/licenses/mit/)
