linux_compat
================================================

A set of extra headers for Cygwin which provides some sort of limited Linux compatibilities.

## Implemented syscall (experimental)

- [x] sendfile (*UNTESTED*)
- [x] prctl (***barely***)

## Won't implement

- [ ] epoll_* (please use other projects, like [cygepoll][cygepoll] (based on [upoll][upoll]), or try to use poll instead.)

[upoll]: https://github.com/richardhundt/upoll
[cygepoll]: https://github.com/fd00/cygepoll
