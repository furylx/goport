# goport, a golang port scanner

A little project I made to train GO!

It is far from done, and I have some ideas, solutions, cleanup to do...and much more...error handling for example ;)

But the basics work! And I am very happy about that.

## Usage

For now only the default mode, stealthscan (SYN scan), is implemented.
There is no service detection, but the "default" values as are used as they are returned by the layers package.


***Mandatory Flags:***

-ip <target> (can be either url or ip)
-I specify the interface please

***Optional Flags:***

-p Here you can single ports, ranges, or with -p - all ports (65k). If you omit -p, the 1000 most frequently used ports are used


## Todo

- cleaning my code and add comments
- change presentation of results (especially if no results)
- tcp-connect scan
- actually implementing icmp (instead of an empty file xD)
- udp scan
- banner grabbing
- automatically detecting interface and handling edge cases (e.g. loopback)


## Disclaimer

I am not actually a dev, and just recently learned coding GO and this little project is meant to improve my coding and understanding of networking. So if someone finds this...thats why things are as they are.
This whole coding happens quite spontaneous, I did not plan or structure beforehand, thats why you will find artifacts (some bigger, some smaller) of ideas that I tried to implement but then had a change of mind for whatever reasons ;)