#!/usr/bin/env python3
"""hook_agent.py — anti-anti-VM environment spoofing.

Two layers:
1. LD_PRELOAD shim (vm_spoof.so, built at image build time) that lies to libc
   calls the sample uses to fingerprint the host (CPU flags, DMI strings, time).
2. Optional Frida instrumentation when a process is instrumentable.

The shim is injected by monitor.py automatically via LD_PRELOAD.
"""

import os
import sys

SHIM_PATH = "/app/vm_spoof.so"


def install_shim() -> bool:
    if os.path.exists(SHIM_PATH):
        os.environ["LD_PRELOAD"] = SHIM_PATH
        os.environ["VM_SPOOF_LOG"] = "/tmp/vm_spoof.log"
        return True
    return False


def apply_frida_hooks(process_name: str = None):
    """Best-effort Frida hooking. Optional; never fatal."""
    try:
        import frida
    except Exception:
        return False

    if not process_name:
        return False
    try:
        session = frida.attach(process_name)
        script = session.create_script(
            """
            var mod = Process.getModuleByName(null);
            Interceptor.replace(Module.findExportByName(null, "getenv"), new NativeCallback(
                function(name) {
                    var env = new NativePointer(name).readCString();
                    if (env && env.indexOf("VMWARE") !== -1) return NULL;
                    var orig = new NativeFunction(Module.findExportByName("libc.so.6", "getenv"), "pointer", ["pointer"]);
                    return orig(name);
                }, "pointer", ["pointer"]));
            """
        )
        script.load()
        return True
    except Exception:
        return False


def main():
    print("[hook_agent] applying anti-anti-VM hooks...", file=sys.stderr)
    shim = install_shim()
    frida_ok = apply_frida_hooks()
    print(json_safe({"shim_installed": shim, "frida_attached": frida_ok}))


def json_safe(payload):
    import json

    return json.dumps(payload)


if __name__ == "__main__":
    main()
