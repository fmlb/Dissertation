import sys
import asyncio
import asyncio.streams
import time
import pickle
import petlib
from os import urandom
from petlib.cipher import Cipher

from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode

from hashlib import sha256
from binascii import hexlify

import msgpack
import encdec
from genzkp import *

from base64 import b64encode

C = EcGroup().generator()



class MyServer:

    def __init__(self):
        self.server = None
        #keeps track of clients
        self.clients = {} # task -> (reader, writer)

    def _accept_client(self, client_reader, client_writer):

        task = asyncio.Task(self._handle_client(client_reader, client_writer))
        self.clients[task] = (client_reader, client_writer)

        def client_done(task):
            print("client task done:", task, file=sys.stderr)
            del self.clients[task]

        task.add_done_callback(client_done)

    @asyncio.coroutine
    def _handle_client(self, client_reader, client_writer):
        global C #This is not good
        global idp_pub #This isnt good either
        while True:
            try:#data = (yield from client_reader.readline()).decode("utf-8")
                data = yield from client_reader.readuntil(separator = b'fireintheboof')
                """print("this is the data")
                print(data[4:-13])"""
                cmd = data[0:4]
                strippedData = data[4:-13]
            except asyncio.streams.IncompleteReadError:
                data = None
            if not data: # an empty string means the client disconnected
                break
            #cmd, *args = str(data).rstrip().split(' ')
            if cmd == b'buys':
                retval = "id"
                client_writer.write("{!r}\n".format(retval).encode("utf-8"))
                start = time.time()
            elif cmd == 'key':
                key = literal_eval(args[0])
                print(key)
                ciphertext = literal_eval(args[1])
                iv, ciphertext, tag = pickle.loads(ciphertext)
                print(type(iv), iv, "\n")
                print(type(ciphertext), ciphertext, "\n")
                print(type(tag), tag, "\n")
                #print(plaintext)
            elif cmd == b'para':
                """G = decode(literal_eval(args[0]))
                q = decode(literal_eval(args[1]))
                g = decode(literal_eval(args[2]))
                h = decode(literal_eval(args[3]))
                z = decode(literal_eval(args[4]))
                hs = decode(literal_eval(args[5]))"""
                listParams = []
                encParams = pickle.loads(strippedData)
                for x in encParams:
                    listParams.append(decode(x))

                params = tuple(listParams)
            elif cmd == b'ipub':

                enc_idp_pub = pickle.loads(strippedData)
                list_enc_idp_pub = []
                for x in enc_idp_pub:
                    list_enc_idp_pub.append(decode(x))

                idp_pub = tuple(list_enc_idp_pub)
            elif cmd == b'vsig':
                enc_sig = pickle.loads(strippedData)
                listSig = []
                for x in enc_sig:
                    listSig.append(decode(x))

                sig = tuple(listSig)

            elif cmd == b'vsg2':
                enc_signature = pickle.loads(strippedData)
                listSignature = []
                for x in enc_signature:
                    listSignature.append(decode(x))

                signature = tuple(listSignature)

                m = BL_verify_cred(params, idp_pub, 2, sig, signature)

                end = time.time()
                finalTime = end-start

                if m != False:
                    print('Proof Correct, time: ', finalTime)
                else:
                    print('Proof Incorrect')


            elif cmd == 'Commitment':
                """params = setup()
                G = params[0]
                C = EcPt.from_binary(literal_eval(args[0]), G)"""
            elif cmd == 'Proof':

                """c = Bn.from_hex(literal_eval(args[0]))
                responses1 = pickle.loads(literal_eval(args[1]))
                params = setup()
                responses = []

                for res in responses1:
                    responses.append(Bn.from_hex(res))

                proof = c, responses
                print(verifyCommitments(params, C, proof))"""

            # This enables us to have flow control in our connection.
            yield from client_writer.drain()

    def start(self, loop):

        self.server = loop.run_until_complete(
            asyncio.streams.start_server(self._accept_client,
                                         '127.0.0.1', 12345,
                                         loop=loop))

    def stop(self, loop):

        if self.server is not None:
            self.server.close()
            loop.run_until_complete(self.server.wait_closed())
            self.server = None

"""def decrypt_AES(key, iv, ciphertext, tag):

    aes=Cipher("aes-128-gcm")
    plaintext = aes.quick_gcm_dec(key, iv, ciphertext, tag)

    print("Plaintext is", str(plaintext).encode("utf-8"))
    return str(plaintext).encode("utf-8")

def setup():

    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(4)]
    o = G.order()
    return (G, g, hs, o)

def to_challenge(elements):

    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)

def verifyCommitments(params, C, proof):

    (G, g, (h0, h1, h2, h3), o) = params
    c, responses = proof
    (r0, r1, r2, r3, rr) = responses
    Cw_prime = c * C + r0 * h0 + r1 * h1 + r2 * h2 + r3 * h3 + rr * g
    c_prime = to_challenge([g, h0, h1, h2, h3, Cw_prime])
    return c_prime == c"""

def BL_show_zk_proof(params, num_attrib):
    (G, _, _, _, _, _) = params

    # Contruct the proof
    zk = ZKProof(G)

    ## The variables

    gam, rnd, R = zk.get(Sec, ["gam", "rnd", "R"])
    attrib = zk.get_array(Sec, "attrib", num_attrib, 0)

    g, z, zet, zet1 = zk.get(ConstGen, ["g", "z", "zet", "zet1"])
    hs = zk.get_array(ConstGen, "hs", num_attrib+1, 0)

    zk.add_proof(zet, gam * z)

    gam_g = zk.get(Gen, "gamg")
    zk.add_proof(gam_g, gam * g)

    gam_hs = zk.get_array(Gen, "gamhs", num_attrib+1, 0)

    for gam_hsi, hsi in zip(gam_hs, hs):
        zk.add_proof(gam_hsi, gam * hsi)

    Cnew = rnd * gam_g + R * gam_hs[0]
    for i, attr in enumerate(attrib):
        Cnew = Cnew + attr * gam_hs[1+i]

    zk.add_proof(zet1, Cnew)
    return zk #we need to send this to the SP

def BL_check_signature(params, idp_pub, signature):
    (G, q, g, h, z, hs) = params
    (y,) = idp_pub
    (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu) = signature

    lhs = (om + omp) % q
    rhs_h = [zet, zet1,
            ro * g + om * y,
            ro1p * g + omp * zet1,
            ro2p * h + omp * zet2, ## problem
            mu * z + omp * zet]

    Hstr = list(map(EcPt.export, rhs_h)) + [m]
    Hhex = b"|".join(map(b64encode, Hstr))
    rhs = Bn.from_binary(sha256(Hhex).digest()) % q

    if rhs == lhs:
        return m
    else:
        return False

def BL_verify_cred(params, issuer_pub, num_attributes, signature, sig):
    m = BL_check_signature(params, issuer_pub, signature)
    assert m != False

    (G, q, g, h, z, hs) = params
    (m, zet, zet1, zet2, om, omp, ro, ro1p, ro2p, mu) = signature

    zk = BL_show_zk_proof(params, num_attributes) #we get this from the user

    env = ZKEnv(zk)

    # Constants
    env.g = g
    env.z = z
    env.zet = zet
    env.zet1 = zet1
    env.hs = hs[:num_attributes + 1]

    ## Extract the proof
    res = zk.verify_proof(env.get(), sig)
    assert res

    return m

def main():
    loop = asyncio.get_event_loop()
    future = asyncio.Future()

    server = MyServer()
    server.start(loop)

    try:
        loop.run_until_complete(future)
        server.stop(loop)
    finally:
        loop.close()


if __name__ == '__main__':
    main()