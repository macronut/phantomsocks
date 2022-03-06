# Configuration for Linux (Localhost mode)
To use phantomsocks on the **hosted machine itself**.
## Set up local dns

Manipulate the system dns into 127.0.0.1 using the way you find convenience.

## Set up NAT rule

`sudo iptables -t nat -A OUTPUT -d X.0.0.0/8 -p tcp -j REDIRECT --to-port 6` (**X** can be any number from 2 - 239, if this do not work, replace **iptables** with **iptables-legacy**, also please try to change the value of **X** if after changing **iptables** into **iptables-legacy**, the redirection still does not work)

## Run phantomsocks

`sudo ./phantomsocks -device Network_Interface -vaddrprefix X -dns 127.0.0.1:53 -redir :6 -c configfile `

(Again, set **X** just as the same above, and replace **Network_Interface** with the network interface you set before)
