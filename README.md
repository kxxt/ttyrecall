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
