# ttyrecall

Recall, but for terminals.

- [Installation Guide](./INSTALL.md)

# Work In Progress!!!

This project is still in its infancy. Bugs, non working features, breaking changes are expected.

For now it can be considered as an asciinema but it is always on, continuously recording your terminals.

# Origin

Inspired by [Microsoft's new controversial recall feature for Windows 11](https://support.microsoft.com/en-us/windows/retrace-your-steps-with-recall-aa03f8a0-a78b-4b3e-b0a1-2eb8ac48701c),
I wonder if I could create something similar for Linux.
It is very resource and compute intensive to continuously capture and analyze screenshots in the background so I prefer
to avoid it. But actually on Linux, we are doing a lot of things in terminals so why not create something similar that
is based on text instead of screenshots?

Before adding AI features(if I ever want to do that), `ttyrecall` will focus on collecting and archiving terminal outputs.
So it can be considered as [asciinema](https://asciinema.org/), but always on.

# Current Status

- [x] Record tty in the background to asciicast-v2 format
- [x] Save the recordings in a directory structure that makes sense
- [x] DAC so that users by default can only access their own recordings. (recording file is owned by `user:ttyrecall`)
- [x] Control which users' tty are recorded via a blocklist or allowlist
- [x] Zstd compression
- [x] A simple systemd service (See `ttyrecall-git` package).
- [x] Stop a recording if it overruns a specified soft budget.

Here is what the collected recordings look like:

```bash
ls -lah /var/lib/ttyrecall/1000/2024/10/04 -lah
total 236K
drwxrwx--- 1 kxxt root  774 Oct  4 22:45 .
drwxrwx--- 1 kxxt root   12 Oct  4 12:52 ..
-rw-rw---- 1 kxxt root  23K Oct  4 22:53 codium-pty6-22:37.cast.zst
-rw-rw---- 1 kxxt root  106 Oct  4 21:57 kded6-pty0-21:53.cast.zst
-rw-rw---- 1 kxxt root 1021 Oct  4 21:57 konsole-pty1-21:56.cast.zst
-rw-rw---- 1 kxxt root  663 Oct  4 21:59 konsole-pty2-21:58.cast.zst
-rw-rw---- 1 kxxt root 8.0K Oct  4 22:01 konsole-pty3-22:00.cast.zst
-rw-rw---- 1 kxxt root  33K Oct  4 22:24 konsole-pty4-22:08.cast.zst
-rw-rw---- 1 kxxt root    0 Oct  4 22:12 konsole-pty5-22:12.cast.zst
-rw-rw---- 1 kxxt root  63K Oct  4 22:50 konsole-pty7-22:42.cast.zst
-rw-rw---- 1 kxxt root  791 Oct  4 12:53 konsole-pty9-12:52.cast.zst
-rw-rw---- 1 kxxt root  779 Oct  4 12:52 sudo-pty11-12:52.cast.zst
-rw-rw---- 1 kxxt root 1.1K Oct  4 22:42 sudo-pty7-22:42.cast.zst
-rw-rw---- 1 kxxt root  31K Oct  4 22:45 sudo-pty8-22:43.cast.zst
-rw-rw---- 1 kxxt root  39K Oct  4 22:51 sudo-pty8-22:45.cast.zst
-rw-rw---- 1 kxxt root  777 Oct  4 12:52 sudo-pty9-12:52-1.cast.zst
-rw-rw---- 1 kxxt root  221 Oct  4 12:53 sudo-pty9-12:53.cast.zst
```

The zstd compressed recordings can be played by the following command:

```bash
zstd -cd /var/lib/ttyrecall/1000/2024/10/03/konsole-pty8-12:19.cast.zst | asciinema play -
```

# TODO

- [ ] Implement a player that could directly take zstd compressed asciicast v2 files.
- [ ] Implement a TUI interface to easily browse and manage the recordings.
- [ ] Implement a web interface to easily browse and manage the recordings.
- [ ] Automatically remove some old recordings in some way.
- [ ] Allow users to sync the recordings to their server.
- [ ] Search for something and we can return some sessions that mentioned it and jump to the corresponding timestamp.
- [ ] Store the recordings in databases or more structured formats to speed up search and indexing.
- [ ] Add AI to it. (Seriously, should I do this????)

# License

Please see the license of the individual crates.

- The eBPF module is licensed under `GPL-2.0-or-later`.
- The xtask crate is also licensed under `GPL-2.0-or-later`.
- The main binary, `ttyrecall`, is licensed under `AGPL-3.0-or-later`.
- The common library, `ttyrecall-common`, is licensed under `MIT-0`(MIT No Attribution).
