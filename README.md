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