# ttyrecall

# Work In Progress!!!

Recall, but for terminals.

Inspired by [Microsoft's new controversial recall feature for Windows 11](https://support.microsoft.com/en-us/windows/retrace-your-steps-with-recall-aa03f8a0-a78b-4b3e-b0a1-2eb8ac48701c),
I wonder if I could create something similar for Linux.
It is very resource and compute intensive to continuously capture and analyze screenshots in the background so I prefer
to avoid it. But actually on Linux, we are doing a lot of things in terminals so why not create something similar that
is based on text instead of screenshots?

Before adding AI features(if I ever want to do that), `ttyrecall` will focus on collecting and archiving terminal outputs.
So it can be considered as [asciinema](https://asciinema.org/), but always on.

# License

Please see the license of the individual crates.

- The eBPF module is licensed under `GPL-2.0-or-later`.
- The xtask crate is also licensed under `GPL-2.0-or-later`.
- The main binary, `ttyrecall`, is licensed under `AGPL-3.0-or-later`.
- The common library, `ttyrecall-common`, is licensed under `MIT-0`(MIT No Attribution).
