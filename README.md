# phantomsocks
A cross-platform proxy client/server for Linux/Windows/macOS with Pcap/RawSocket/WinDivert
## Usage
```
./phantomsocks -h
Usage of ./phantomsocks:
  -log int
    	LogLevel
  -maxprocs int
    	MaxProcesses
  -install
    	Install service (Windows)
  -remove
    	Remove service (Windows)
  -start
    	Start service (Windows)
  -stop
    	Stop service (Windows)
```
## Configure
### config.json:
```
{
    "vaddrprefix": 6,
    "proxy": "socks://address:port",
    "profiles": ["1.conf", "2.conf", "3.conf"],
    "inbounds": [
        {
            "name": "dns",
            "protocol": "dns",
            "address": "127.0.0.1:5353"
        },
        {
            "name": "socks",
            "protocol": "socks",
            "address": "127.0.0.1:1081"
        },
        {
            "name": "redirect",
            "protocol": "redirect",
            "address": "0.0.0.0:6"
        },
        {
            "name": "tproxy",
            "protocol": "tproxy",
            "address": "0.0.0.0:7"
        }
    ],
    "outbounds": [
        {
            "name": "default",
            "dns": "udp://8.8.8.8:53"
        },
        {
            "name": "https",
            "dns": "udp://8.8.8.8:53",
            "device": "eth0",
            "hint": "https"
        },
        {
            "name": "doh",
            "dns": "https://cloudflare-dns.com/dns-query"
        },
        {
            "name": "dot",
            "dns": "tls://8.8.8.8:853"
        },
        {
            "name": "ecs",
            "dns": "udp://8.8.8.8:53/?ecs=35.190.247.1"
        },
        {
            "name": "socks5",
            "protocol": "socks5",
            "address": "127.0.0.1:1080"
        },
        {
            "name": "socks4",
            "dns": "udp://8.8.8.8:53",
            "protocol": "socks4",
            "address": "127.0.0.1:1080"
        }
    ]
}
```
### Socks:
```
Windows:
config.json:
    "proxy" :"socks://127.0.0.1:1080/?dns=127.0.0.1",
    "inbounds": [
        {
            "name": "DNS",
            "protocol": "dns",
            "address": "127.0.0.1:53"
        },
        {
            "name": "Socks",
            "protocol": "socks",
            "address": "127.0.0.1:1080"
        }
    ]

macOS:
config.json:
    "proxy": "socks://127.0.0.1:1080",
    "inbounds": [
        {
            "name": "Socks",
            "protocol": "socks",
            "address": "127.0.0.1:1080"
        }
    ]
```
### Redirect:
```
Linux:
iptables -t nat -A OUTPUT -d 6.0.0.0/8 -p tcp -j REDIRECT --to-port 6
config.json:
    "vaddrprefix": 6,
    "inbounds": [
        {
            "name": "DNS",
            "protocol": "dns",
            "address": "127.0.0.1:53"
        },
        {
            "name": "Redirect",
            "protocol": "redirect",
            "address": "0.0.0.0:6"
        }
    ]

Windows(windivert):
config.json:
    "vaddrprefix": 6,
    "proxy": "redirect://6.0.0.0:6",
    "inbounds": [
        {
            "name": "Redirect",
            "protocol": "redirect",
            "address": "0.0.0.0:6"
        }
    ]
```
### Local Redirect (unsafe):
```
config.json:
    "vaddrprefix": 127,
    "proxy": "dns://127.0.0.1/?if=Ethernet",
    "inbounds": [
        {
            "name": "Redirect",
            "protocol": "redirect",
            "address": "0.0.0.0:443"
        }
    ]
```
### Rules
```
  [default]         #domains below will use the config of this interface
  domain=ip,ip,...  #this domain will use these IPs
  domain            #this domain will be resolved by DNS
  domain=[domain]   #this domain will use the config of this domain
  domain=domain     #this domain will use the addresses of this domain
  
  [dot]             #domains below will use the config of dot
  domain
  [socks5]          #domains below will use the config of socks5
  domain
```
## Installation
go get github.com/macronut/phantomsocks

## Compile
cd $GOPATH/src/github.com/macronut/phantomsocks/

go build

### pcap version
static linking for pcap
```
sudo apt-get install -y libpcap-dev
go build -tags pcap -ldflags '-extldflags "-static"'
```
### raw socket version
raw socket is Linux only
```
go build -tags rawsocket
```
### windivert version
windivert is Windows only
```
env GOOS=windows GOARCH=amd64 go build -tags windivert
```

### cross & static compile pcap version on Ubuntu 18.04
Install dependencies
```
apt-get install git autoconf automake bison build-essential flex gawk gettext gperf libtool pkg-config libpcap-dev
```
Download & uncompress tool-chain
```
cd ~/Downloads
wget https://downloads.openwrt.org/releases/19.07.2/targets/ramips/mt7621/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64.tar.xz
tar -xJvf openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64.tar.xz
```
Set environment variable
```
export PATH=$PATH:~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl/bin: && export STAGING_DIR=~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl
```
Download & uncompress libpcap
```
wget https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz
tar -xzvf libpcap-1.9.1.tar.gz
```
Build libpcap
```
cd libpcap-1.9.1
./configure --host=mipsel-openwrt-linux-musl --prefix='~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl'
make && make install 
```
Build phantomsocks
```
cd ~/go/src/github.com/Macronut/phantomsocks
env GOOS=linux GOARCH=mipsle CGO_ENABLED=1 CC='~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl/bin/mipsel-openwrt-linux-gcc'  go build  -ldflags '-extldflags "-static"'
```
