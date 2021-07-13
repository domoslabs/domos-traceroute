# Domos Traceroute
A traceroute by Domos which can control per flow ECMP, and that way map paths to an endpoint. TCP only for now.
## Installation
Clone the repo and all its submodules:
```bash
git clone --recurse-submodules https://github.com/domoslabs/domos-traceroute.git 
```
Then using cmake:
```bash
mkdir build
cd build
cmake ..
make
```
This outputs an executable.

Optional:
```bash
make install
```
## Usage
Requires root access.

To show the help message:
```bash
./domos-traceroute -h
```