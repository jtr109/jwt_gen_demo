import time

from Crypto.PublicKey import RSA
from jwcrypto import jwk, jwt


def create_private_pem():
    return RSA.generate(2048).export_key()


def create_jwk(private_pem: bytes):
    return jwk.JWK.from_pem(private_pem)


def generate_jwt(duration: int = 3600, **kwargs):
    exp = int(time.time()) + duration
    payload = dict(exp=exp)
    payload.update(kwargs)
    return jwt.JWT(header=dict(alg='RS256', typ='JWT', kid=key.key_id), claims=payload)


if __name__ == "__main__":
    pem_path = './mock/key.pem'

    # # 生成 pem
    # pem = create_private_pem()
    # with open(pem_path, 'wb') as f:
    #     f.write(pem)

    # 生成 jwk
    with open(pem_path, 'rb') as f:
        pem_data = f.read()
    encoded_pem_data = pem_data.encode()
    key = create_jwk(encoded_pem_data)
    with open('./mock/jwks.json', 'wb') as f:
        f.write(key.export_public().encode())

    # 生成 jwt
    token = generate_jwt()
    token.make_signed_token(key)
    print(token.serialize())
