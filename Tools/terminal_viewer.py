#!/usr/bin/env python3

"""
Terminal viewer for ESP32 data logs.
Watches `esp32_logs/data.json` and prints newly added entries in a Rust-style struct.
"""
import json
import time
import os
import argparse
import textwrap


def format_rust(name, obj, indent=0):
    pad = ' ' * indent
    if isinstance(obj, dict):
        lines = [f"{pad}{name} {{"]
        for k, v in obj.items():
            lines.append(format_rust(f"{k}", v, indent + 4))
        lines.append(f"{pad}}}")
        return "\n".join(lines)
    elif isinstance(obj, list):
        if not obj:
            return f"{pad}{name}: []"
        items = []
        for v in obj:
            items.append(format_rust("-", v, indent + 4))
        return f"{pad}{name}: [\n" + "\n".join(items) + f"\n{pad}]"
    else:
        # Scalars
        if isinstance(obj, str):
            val = f'"{obj}"'
        else:
            val = str(obj)
        return f"{pad}{name}: {val}"


def print_entry(i, entry):
    header = f"Entry #{i}"
    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))

    # Common fields printed prominently
    if isinstance(entry, dict):
        # Try to show an envelope-like compact view
        algo = entry.get('algo') or entry.get('algorithm')
        npub = entry.get('npub')
        ct = entry.get('ct')
        payload = entry.get('payload') or entry.get('data') or entry.get('plaintext') or entry

        if algo:
            print(f"algo: {algo}")
        if npub:
            print(f"npub: {npub[:24]}{'...' if len(npub)>24 else ''}")
        if ct:
            print(f"ct_len: {len(ct)}")

        # Pretty-print payload in Rust-struct style
        print(format_rust('payload', payload, indent=0))
    else:
        print(format_rust('value', entry, indent=0))


def follow_file(path, poll=1.0):
    last_mtime = 0
    last_count = 0
    while True:
        try:
            if not os.path.exists(path):
                print(f"Waiting for {path} to appear...")
                time.sleep(poll)
                continue

            mtime = os.path.getmtime(path)
            if mtime != last_mtime:
                last_mtime = mtime
                with open(path, 'r') as f:
                    try:
                        data = json.load(f)
                    except Exception:
                        # file might be a stream of JSON lines; try lines
                        f.seek(0)
                        data = []
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data.append(json.loads(line))
                            except Exception:
                                # skip unparsable lines
                                pass

                if isinstance(data, dict):
                    # single object -> treat as one entry
                    data_list = [data]
                else:
                    data_list = data

                # print only new entries
                for i in range(last_count, len(data_list)):
                    print_entry(i + 1, data_list[i])

                last_count = len(data_list)

        except KeyboardInterrupt:
            print('\nexiting viewer')
            return
        except Exception as e:
            print(f"viewer error: {e}")
        time.sleep(poll)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Terminal viewer for ESP32 logs')
    parser.add_argument('--file', '-f', default='esp32_logs/data.json', help='Path to data.json')
    parser.add_argument('--poll', '-p', type=float, default=1.0, help='Poll interval seconds')
    args = parser.parse_args()

    print('Starting terminal viewer. Press Ctrl-C to quit.')
    follow_file(args.file, poll=args.poll)
# Load optional device->user mapping from workspace file
DEVICE_MAP = {}
def load_device_map(path='device_map.json'):
    global DEVICE_MAP
    try:
        if os.path.exists(path):
            with open(path, 'r') as f:
                DEVICE_MAP = json.load(f)
    except Exception:
        DEVICE_MAP = {}


# Ascon CLI helper
ASCON_CLI_PATH = None
DEFAULT_ASCON_KEYHEX = "000102030405060708090a0b0c0d0e0f"
def find_ascon_cli():
    global ASCON_CLI_PATH
    if ASCON_CLI_PATH:
        return ASCON_CLI_PATH
    # Check next to this script
    candidate = Path(__file__).with_name('ascon_cli')
    if candidate.exists() and os.access(str(candidate), os.X_OK):
        ASCON_CLI_PATH = str(candidate)
        return ASCON_CLI_PATH
    # Check PATH
    found = shutil.which('ascon_cli')
    if found:
        ASCON_CLI_PATH = found
        return ASCON_CLI_PATH
    return None


def decrypt_with_cli(ct_hex: str, npub_hex: str, keyhex: str = DEFAULT_ASCON_KEYHEX) -> str:
    cli = find_ascon_cli()
    if not cli:
        raise FileNotFoundError('ascon_cli not found')
    # ascon_cli dec <keyhex> <npubhex> <cthex>
    proc = subprocess.run([cli, 'dec', keyhex, npub_hex, ct_hex], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f'ascon_cli failed: {proc.stderr.strip()}')
    return proc.stdout.strip()


def format_rust(name, obj, indent=0):
    pad = ' ' * indent
    if isinstance(obj, dict):
        lines = [f"{pad}{name} {{"]
        for k, v in obj.items():
            lines.append(format_rust(f"{k}", v, indent + 4))
        lines.append(f"{pad}}}")
        return "\n".join(lines)
    elif isinstance(obj, list):
        if not obj:
            return f"{pad}{name}: []"
        items = []
        for v in obj:
            items.append(format_rust("-", v, indent + 4))
        return f"{pad}{name}: [\n" + "\n".join(items) + f"\n{pad}]"
    else:
        # Scalars
        if isinstance(obj, str):
            val = f'"{obj}"'
        else:
            val = str(obj)
        return f"{pad}{name}: {val}"


def print_entry(i, entry):
    header = f"Entry #{i}"
    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))

    # Common fields printed prominently
    if isinstance(entry, dict):
        # Try to show an envelope-like compact view
        algo = entry.get('algo') or entry.get('algorithm')
        npub = entry.get('npub')
        ct = entry.get('ct')
        payload = entry.get('payload') or entry.get('data') or entry.get('plaintext') or entry

        if algo:
            print(f"algo: {algo}")
        if npub:
            print(f"npub: {npub[:24]}{'...' if len(npub)>24 else ''}")
        if ct:
            print(f"ct_len: {len(ct)}")

        # Try to decrypt using local ascon_cli and show plaintext if available
        if algo and algo.upper().startswith('ASCON') and ct and npub:
            try:
                plain = decrypt_with_cli(ct, npub)
                try:
                    parsed = json.loads(plain)
                    print("plaintext:")
                    print(format_rust('plaintext', parsed, indent=0))
                except Exception:
                    print(f"plaintext: {plain}")
            except Exception as e:
                print(f"(ascon_cli unavailable or decryption failed: {e})")

        # Show device identification if present
        device_id = None
        if isinstance(payload, dict):
            device_id = payload.get('device_id') or payload.get('mac') or payload.get('device')

        if device_id:
            user = DEVICE_MAP.get(device_id, None)
            print(f"device_id: {device_id}{' ('+user+')' if user else ''}")

        # Show source IP if receiver attached it
        source_ip = None
        if isinstance(payload, dict):
            source_ip = payload.get('source_ip') or (payload.get('_envelope') or {}).get('source_ip')
        if not source_ip and isinstance(entry, dict):
            # top-level entry may contain source_ip (when viewer gets full saved object)
            source_ip = entry.get('source_ip')
        if source_ip:
            print(f"source_ip: {source_ip}")

        # Pretty-print payload in Rust-struct style
        print(format_rust('payload', payload, indent=0))
    else:
        print(format_rust('value', entry, indent=0))


def follow_file(path, poll=1.0):
    last_mtime = 0
    last_count = 0
    while True:
        try:
            if not os.path.exists(path):
                print(f"Waiting for {path} to appear...")
                time.sleep(poll)
                continue

            mtime = os.path.getmtime(path)
            if mtime != last_mtime:
                last_mtime = mtime
                with open(path, 'r') as f:
                    try:
                        data = json.load(f)
                    except Exception:
                        # file might be a stream of JSON lines; try lines
                        f.seek(0)
                        data = []
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data.append(json.loads(line))
                            except Exception:
                                # skip unparsable lines
                                pass

                if isinstance(data, dict):
                    # single object -> treat as one entry
                    data_list = [data]
                else:
                    data_list = data

                # print only new entries
                for i in range(last_count, len(data_list)):
                    print_entry(i + 1, data_list[i])

                last_count = len(data_list)

        except KeyboardInterrupt:
            print('\nexiting viewer')
            return
        except Exception as e:
            print(f"viewer error: {e}")
        time.sleep(poll)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Terminal viewer for ESP32 logs')
    parser.add_argument('--file', '-f', default='esp32_logs/data.json', help='Path to data.json')
    parser.add_argument('--poll', '-p', type=float, default=1.0, help='Poll interval seconds')
    args = parser.parse_args()

    print('Starting terminal viewer. Press Ctrl-C to quit.')
    # load optional device->user mapping
    load_device_map()
    follow_file(args.file, poll=args.poll)
