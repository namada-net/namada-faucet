from requests import get, post
from hashlib import sha256
import argparse
import json

DEFAULT_URL = "http://0.0.0.0:5000/api/v1/faucet"

def request_challenge(url):
    return get(url).json()

def request_transfer(url, data):
    return post(url, json=data)

def is_valid_pow(solution, difficulty):
    for i in range(0, difficulty):
        if solution[i] != 0:
            return False
    return True

def compute_pow_solution(challenge, difficulty):
    challenge_bytes = bytes.fromhex(challenge)
    i = 0
    while i >= 0:
        hasher = sha256()
        hasher.update(challenge_bytes)
        hasher.update(i.to_bytes(64, byteorder='big'))
        hash = hasher.digest()

        valid = is_valid_pow(hash, difficulty)
        if valid:
            return i.to_bytes(64, byteorder='big').hex()
        i += 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Request an amount of token from faucet.')
    parser.add_argument('url', action='store', type=str, default=DEFAULT_URL, help='The faucet url.')
    parser.add_argument('token', action='store', type=str, help='The token address.')
    parser.add_argument('amount', action='store', type=int, default=1000, help='The token amount.')
    parser.add_argument('target', action='store', type=str, help='The target address.')

    args = parser.parse_args()

    response = request_challenge(args.url)
    solution = compute_pow_solution(response['challenge'], 2)
    response = request_transfer(args.url, {
        'solution': solution,
        'tag': response['tag'],
        'challenge': response['challenge'],
        'transfer': {
            'target': args.target,
            'token': args.token,
            'amount': args.amount * 10**6
        }
    })

    print(json.dumps(response.json(), indent=2))
