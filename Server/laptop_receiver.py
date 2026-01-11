#!/usr/bin/env python3


from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime
import os
from pathlib import Path
from binascii import unhexlify
import subprocess
import shutil

from Crypto.Cipher import AES
from Crypto.Util import Counter


ASCON_CLI_PATH = Path(__file__).with_name("ascon_cli")
ASCON_KEY = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
])
ENC_KEY = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE])
INTEGRITY_KEY = "shared-key-01"


app = Flask(__name__)

# Configure logging
log_dir = "esp32_logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'esp32_data.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


data_storage = {
    'temperature_readings': [],
    'cipher_tests': [],
    'all_data': []
}


def compute_integrity_hash(payload_str: str) -> str:
    """Compute djb2-style hash to match ESP32 implementation."""
    h = 5381
    for ch in INTEGRITY_KEY:
        h = ((h << 5) + h) ^ ord(ch)
        h &= 0xFFFFFFFF
    for ch in payload_str:
        h = ((h << 5) + h) ^ ord(ch)
        h &= 0xFFFFFFFF
    return f"{h:08x}"


def decrypt_payload(enc_hex: str, iv_hex: str) -> str:
    ct = unhexlify(enc_hex)
    iv = unhexlify(iv_hex)
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"), little_endian=False)
    cipher = AES.new(ENC_KEY, AES.MODE_CTR, counter=ctr)
    pt = cipher.decrypt(ct)
    return pt.decode('utf-8')


def find_ascon_cli():
    candidate = ASCON_CLI_PATH
    if candidate.exists() and os.access(str(candidate), os.X_OK):
        return str(candidate)
    found = shutil.which('ascon_cli')
    if found:
        return found
    return None


def decrypt_with_cli(ct_hex: str, npub_hex: str, keyhex: str = None) -> str:
    if keyhex is None:
        keyhex = ''.join(f"{b:02x}" for b in ASCON_KEY)
    cli = find_ascon_cli()
    if not cli:
        raise FileNotFoundError('ascon_cli not found.  ')
    proc = subprocess.run([str(cli), 'dec', keyhex, npub_hex, ct_hex], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or 'ascon_cli failed')
    return proc.stdout.strip()


# Prefer Python ascon package if available, else fallback to CLI
try:
    import ascon as ascon_pkg
except Exception:
    ascon_pkg = None


def decrypt_ascon(ct_hex: str, npub_hex: str) -> str:
    # Prefer CLI if available (guaranteed compatible with ESP implementation)
    cli = find_ascon_cli()
    if cli:
        return decrypt_with_cli(ct_hex, npub_hex)
    # Fall back to Python package
    if ascon_pkg is not None:
        ct = unhexlify(ct_hex)
        npub = unhexlify(npub_hex)
        if len(npub) != 16:
            raise ValueError("Ascon nonce must be 16 bytes")
        pt = ascon_pkg.decrypt(ASCON_KEY, npub, b"", ct, variant="Ascon-128a")
        if pt is None:
            raise RuntimeError("Ascon auth failed (Python pkg returned None)")
        return pt.decode('utf-8')
    raise RuntimeError("No Ascon implementation available; build ascon_cli or pip install ascon")


@app.route('/data', methods=['POST'])
def receive_data():
    """Receive JSON data from ESP32"""
    try:
        data = request.get_json()

        if data is None:
            return jsonify({'status': 'error', 'message': 'No JSON data received'}), 400

        decrypted_obj = None
        if isinstance(data, dict) and data.get('algo') == 'ASCON-128A' and 'ct' in data and 'npub' in data:
            logger.info("ASCON envelope ct=%s npub=%s", data.get('ct'), data.get('npub'))
            try:
                plaintext = decrypt_ascon(data['ct'], data['npub'])
                decrypted_obj = json.loads(plaintext)
                data = decrypted_obj
            except Exception as e:
                logger.error("Ascon decrypt/parse failed: %s", str(e))
                return jsonify({'status': 'error', 'message': f'ascon decrypt failed: {e}',
                                'ct': data.get('ct'), 'npub': data.get('npub')}), 400
        elif isinstance(data, dict) and 'enc' in data and 'iv' in data:
            logger.info("AES envelope enc=%s iv=%s", data.get('enc'), data.get('iv'))
            try:
                plaintext = decrypt_payload(data['enc'], data['iv'])
                decrypted_obj = json.loads(plaintext)
                data = decrypted_obj
            except Exception as e:
                logger.error("Decrypt/parse failed: %s", str(e))
                return jsonify({'status': 'error', 'message': f'decrypt failed: {e}'}), 400

        data['received_at'] = datetime.now().isoformat()
        logger.info(f"Received: {json.dumps(data)}")

        integrity_ok = None
        if data.get('type') == 'test':
            try:
                base_str = ("{\"type\":\"test\",\"message_id\":%d,\"test_number\":%d,"
                            "\"timestamp\":%d,\"test_data\":\"%s\",\"rssi\":%d}") % (
                    int(data.get('message_id', 0)),
                    int(data.get('test_number', 0)),
                    int(data.get('timestamp', 0)),
                    str(data.get('test_data', "")),
                    int(data.get('rssi', 0))
                )
                expected = compute_integrity_hash(base_str)
                provided = str(data.get('integrity_hash', '')).lower()
                integrity_ok = (provided == expected)
                data['integrity_ok'] = integrity_ok
                if not integrity_ok:
                    data['integrity_expected'] = expected
                    logger.warning("Integrity check failed for message_id=%s (provided=%s expected=%s)",
                                   data.get('message_id'), provided, expected)
                else:
                    logger.info("Integrity ok for message_id=%s", data.get('message_id'))
            except Exception as e:
                integrity_ok = False
                data['integrity_ok'] = False
                data['integrity_error'] = str(e)
                logger.error("Integrity verification error: %s", str(e))

        if data.get('type') == 'temperature':
            data_storage['temperature_readings'].append(data)
            logger.info(f"Temperature: {data.get('temperature')}°C at {data.get('timestamp')}s")
        elif data.get('test') == 'Ascon AEAD':
            data_storage['cipher_tests'].append(data)
            logger.info(f"Cipher Test: Encryption={data.get('encryption_result')}, "
                       f"Decryption={data.get('decryption_result')}, "
                       f"Tamper={data.get('tamper_detected')}")
        elif data.get('type') == 'test':
            data_storage['cipher_tests'].append(data)
            logger.info(f"Test msg id={data.get('message_id')} integrity={integrity_ok}")

        data_storage['all_data'].append(data)

        with open(os.path.join(log_dir, 'data.json'), 'w') as f:
            json.dump(data_storage, f, indent=2)

        response = {'status': 'success', 'message': 'Data received and logged'}
        if integrity_ok is not None:
            response['integrity_ok'] = integrity_ok
        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/stats', methods=['GET'])
def get_stats():
    stats = {
        'total_readings': len(data_storage['all_data']),
        'temperature_readings': len(data_storage['temperature_readings']),
        'cipher_tests': len(data_storage['cipher_tests']),
        'data': data_storage
    }
    return jsonify(stats), 200


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'online', 'timestamp': datetime.now().isoformat()}), 200


if __name__ == '__main__':
    logger.info("Starting ESP32 Data Receiver on 0.0.0.0:8080")
    logger.info("Waiting for data from ESP32...")
    logger.info(f"Data will be stored in '{log_dir}' directory")
    app.run(host='0.0.0.0', port=8080, debug=False)

