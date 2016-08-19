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

import matplotlib.pyplot as plt

C = EcGroup().generator()

timeList = []



class MyServer:

    def __init__(self):
        self.server = None
        #keeps track of clients
        self.clients = {} # task -> (reader, writer)

    def _accept_client(self, client_reader, client_writer):

        task = asyncio.Task(self._handle_client(client_reader, client_writer))
        self.clients[task] = (client_reader, client_writer)

        def client_done(task):
            #print("client task done:", task, file=sys.stderr)
            del self.clients[task]

        task.add_done_callback(client_done)

    @asyncio.coroutine
    def _handle_client(self, client_reader, client_writer):
        global count
        global paramsReceived
        IOtime = 0
        while True:
            try:#data = (yield from client_reader.readline()).decode("utf-8")
                startWait = time.time()
                data = yield from client_reader.readuntil(separator=b'fireintheboof')
                endWait = time.time()
                #print('IO wait: ', data[0:4], endWait - startWait)
                IOtime += endWait-startWait

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

                count +=1
                id = count

                print(id, 'Starting...')

            elif cmd == b'para':

                params = decode(strippedData)

                paramsReceived = True

            elif cmd == b'ipub':

                idp_pub = decode(strippedData)

            elif cmd == b'vsig':

                sig = decode(strippedData)

            elif cmd == b'vsg2':

                signature = decode(strippedData)
                startSigProof = time.time()
                m = BL_verify_cred(params, idp_pub, 2, sig, signature)
                endSigProof = time.time()
                finalSigProof = endSigProof - startSigProof

                if m != False:
                    print('Signature Correct')
                else:
                    print('Signature Incorrect')

            elif cmd == b'page':

                newStuff = decode(strippedData)
                c, responses, gam_g, gam_hs, Age, xran = newStuff
                rrnd, rR, rx = responses
                #print(gam_hs, Age)

                (G, q, g, h, z, hs) = params

                startProof = time.time()

                H = G.hash_to_point(b'service_name')
                ID = xran * H

                zet1 = sig[2]

                zet1p = zet1 - Age * gam_hs[2]

                Waprime = rrnd * gam_g + rR * gam_hs[0] + rx * gam_hs[1] + c * zet1p

                Wxprime = rx * H + c * ID

                stuffToHash = (gam_g, Waprime, Wxprime, zet1p, gam_hs[0], gam_hs[1], gam_hs[2], H)
                cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
                chash = sha256(cstr).digest()
                c_prime = Bn.from_binary(chash)

                if c == c_prime:
                    end = time.time()
                    finalTime = end-start
                    timeList.append(finalTime)
                    print(id, "Age & User match, time: ", finalTime, 'Time for proof: ', end - startProof, 'Sig proof: ', finalSigProof, 'IO time: ', IOtime)
                else:
                    print("whops")


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

def BL_verify_age(params, issuer_pub, num_attributes, signature, sig, gam_hs, zet1p, gam_g):
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
    env.zet1 = zet1p
    env.hs = gam_hs[:num_attributes + 1]

    ## Extract the proof
    res = zk.verify_proof(env.get(), sig)
    assert res

    lhs = (om + omp) % q
    rhs_h = [zet, zet1,
             ro * g + om * y,
             ro1p * g + omp * zet1,
             ro2p * h + omp * zet2,  ## problem
             mu * z + omp * zet]

    Hstr = list(map(EcPt.export, rhs_h)) + [m]
    Hhex = b"|".join(map(b64encode, Hstr))
    rhs = Bn.from_binary(sha256(Hhex).digest()) % q

    # Check the (future) ZK proof
    # assert rnd * gam_g + R * gam_hs[0] + L1 * gam_hs[1] + L2 * gam_hs[2] == zet1
    assert rnd * gam_g + R * gam_hs[0] + L1 * gam_hs[1] == zet1 - Age * gam_hs[2]

    return m

def main():
    global paramsReceived
    global count
    paramsReceived = False
    count = 0
    loop = asyncio.get_event_loop()
    future = asyncio.Future()

    server = MyServer()
    server.start(loop)

    try:
        loop.run_until_complete(future)
        server.stop(loop)
    finally:
        loop.close()
        plt.plot(timeList)
        plt.ylabel('numbers')
        plt.savefig('409.png')


if __name__ == '__main__':
    main()