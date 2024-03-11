# CVE-2018-6574-go-get-RCE
The issue is due to the fact that when installing a package, Golang will build native extensions. This can be used to pass additional flags to the compiler to gain code execution. For example, CFLAGS can be used.

You can build it using the following command:
$ gcc -shared -o attack.so -fPIC attack.c
Once you host your full payload on Github, you should be able to pass the package link to the victim.

