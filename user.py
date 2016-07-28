import asyncio
import asyncio.streams
import sys
import petlib
from os import urandom
from petlib.cipher import Cipher
import pickle
from ast import literal_eval

from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
from base64 import b64encode
from petlib.pack import encode, decode

from hashlib import sha256
from binascii import hexlify

import time
import encdec
from genzkp import *

loop = asyncio.get_event_loop()

"""#for encryption
def keyGen():

    key = urandom(16)
    #keyEscaped = literal_eval(repr(key).replace(~~~))
    #Sometimes I get an EOL while scanning strin literal error, will need to escape charactesr

    return key

#for encryption
def encrypt_AES(key, msg):

    plaintext = msg.encode("utf-8")
    aes = Cipher("aes-128-gcm")
    iv = urandom(16)
    ciphertext, tag = aes.quick_gcm_enc(key, iv, plaintext)
    print(type(iv), iv, "\n")
    print(type(ciphertext), ciphertext, "\n")
    print(type(tag), tag, "\n")

    return (iv, ciphertext, tag)


def setup():
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(4)]
    o = G.order()
    return (G, g, hs, o)

def proveCommitment(params, C, r, secrets):
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets

    #generate random values
    w0 = o.random()
    w1 = o.random()
    w2 = o.random()
    w3 = o.random()
    wr = o.random()

    #compute W
    wBig = w0 * h0 + w1 * h1 + w2 * h2 + w3 * h3 + wr * g


    #compute challenge c
    stuffToHash = (g, h0, h1, h2, h3, wBig)
    cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
    chash = sha256(cstr).digest()
    c = Bn.from_binary(chash)

    #compute responses
    r0 = w0 - c*x0
    r1 = w1 - c*x1
    r2 = w2 - c*x2
    r3 = w3 - c*x3
    rr = wr - c*r

    responses = (r0, r1, r2, r3, rr)

    #convert this proof into something we can send over the socket:
    newResponses = []
    for res in responses:
        newResponses.append(Bn.hex(res))

    newc = Bn.hex(c)

    return (newc, newResponses)"""

class StateHolder(object):
    pass

def BL_setup(Gid = 713):
    G = EcGroup(Gid)
    q = G.order()

    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    z = G.hash_to_point(b"z")
    hs = [G.hash_to_point(("h%s" % i).encode("utf-8")) for i in range(100)]#what is this

    return (G, q, g, h, z, hs)

def BL_user_setup(params, attributes):
    (G, q, g, h, z, hs) = params

    R = q.random()
    C = R * hs[0] #something extra here???

    for (i, attrib_i) in enumerate(attributes):
        C = C + attrib_i * hs[1+i]

    user_state = StateHolder()
    user_state.params = params
    user_state.attributes = attributes
    user_state.C = C
    user_state.R = R

    return user_state, (C, )

def BL_user_prep(user_state, msg_from_idp):
    (G, q, g, h, z, hs) = user_state.params
    (rnd, ) = msg_from_idp
    C = user_state.C

    z1 = C + rnd * g
    gam = q.random()
    zet = gam * z
    zet1 = gam * z1
    zet2 = zet + (-zet1)
    tau = q.random()
    eta = tau * z

    user_state.z1 = z1
    user_state.gam = gam
    user_state.zet = zet
    user_state.zet1 = zet1
    user_state.zet2 = zet2
    user_state.tau = tau
    user_state.eta = eta

    user_state.rnd = rnd

def BL_user_validation(user_state, idp_pub, msg_to_user, message=b''):
    (G, q, g, h, z, hs) = user_state.params
     # (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state
    (a, a1p, a2p) = msg_to_user
    (y,) = idp_pub

    assert G.check_point(a)
    assert G.check_point(a1p)
    assert G.check_point(a2p)

    t1,t2,t3,t4,t5 = [q.random() for _ in range(5)]
    print(type(a), type(t1), type(g), type(t2), type(y))
    alph = a + t1 * g + t2 * y
    alph1 = user_state.gam * a1p + t3 * g + t4 * user_state.zet1
    alph2 = user_state.gam * a2p + t5 * h + t4 * user_state.zet2

    # Make epsilon
    H = [user_state.zet, user_state.zet1, alph, alph1, alph2, user_state.eta]
    Hstr = list(map(EcPt.export, H)) + [message]
    Hhex = b"|".join(map(b64encode, Hstr))
    epsilon = Bn.from_binary(sha256(Hhex).digest()) % q

    e = epsilon.mod_sub(t2,q).mod_sub(t4, q)

    user_state.ts = [t1, t2, t3, t4, t5]
    user_state.message = message

    msg_to_issuer = e
    return msg_to_issuer

def BL_user_validation_2(user_state, msg_from_idp):
    (G, q, g, h, z, hs) = user_state.params
    (c, r, cp, r1p, r2p) = msg_from_idp
    (t1,t2,t3,t4,t5), m = user_state.ts, user_state.message

    # (z1, gam, zet, zet1, zet2, tau, eta) = user_private_state

    gam = user_state.gam

    ro = r.mod_add(t1,q)
    om = c.mod_add(t2,q)
    ro1p = (gam * r1p + t3) % q
    ro2p = (gam * r2p + t5) % q
    omp = (cp + t4) % q
    mu = (user_state.tau - omp * gam) % q

    signature = (m, user_state.zet,
                    user_state.zet1,
                    user_state.zet2, om, omp, ro, ro1p, ro2p, mu)

    return signature

def BL_cred_proof(user_state):
    (G, q, g, h, z, hs) = user_state.params
    gam = user_state.gam

    assert user_state.zet == user_state.gam * z
    gam_hs = [gam * hsi for hsi in hs]
    gam_g = gam * g

    Cnew = user_state.rnd * gam_g + user_state.R * gam_hs[0]
    for i, attr in enumerate(user_state.attributes):
        Cnew = Cnew + attr * gam_hs[1+i]

    assert Cnew == user_state.zet1

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

def BL_user_prove_cred(user_state):
    (G, q, g, h, z, hs) = user_state.params
    zk = BL_show_zk_proof(user_state.params, len(user_state.attributes))

    env = ZKEnv(zk)

    # The secrets
    env.gam = user_state.gam
    env.rnd = user_state.rnd
    env.R   = user_state.R
    env.attrib = user_state.attributes

    # Constants
    env.g = g
    env.z = z
    env.zet = user_state.zet
    env.zet1 = user_state.zet1
    env.hs = hs[:len(user_state.attributes) + 1]

    # The stored generators
    env.gamg = user_state.gam * g
    env.gamhs = gam_hs = [user_state.gam * hsi for hsi in hs[:len(user_state.attributes) + 1]]

    ## Extract the proof
    sig = zk.build_proof(env.get())
    if __debug__:
        assert zk.verify_proof(env.get(), sig, strict=False)

    return sig

@asyncio.coroutine
def client():
    reader, writer = yield from asyncio.streams.open_connection(
        '127.0.0.1', 12345, loop=loop)#Service Provider
    reader2, writer2 = yield from asyncio.streams.open_connection(
        '127.0.0.1', 7878, loop=loop)#Identity Provider

    def send(msg, writer):
        print("> " + str(msg))
        writer.write((msg + '\n').encode("utf-8"))
        print(msg)
        print(type(msg.encode("utf8")))

    def sendBin(data, writer):
        print("bin>" + str(data))
        writer.write(data + b'fireintheboof')
        #writer.write_eof()
        print(data + b'fireintheboof')
        print(type(data + b'fireintheboof'))

    def recv(reader):
        msgback = (yield from reader.readline()).decode("utf-8").rstrip()
        print("< " + msgback)
        return msgback

    # send a line
    #send("buy", writer)
    sendBin(b'buys', writer)
    msg = yield from recv(reader)
    if repr('id') == msg:
        print("ok i go get ID")

        #generating, encoding, and sending parameters to both sp and idp
        params = BL_setup()
        print(params)
        encParams = []
        for x in params:
            encParams.append(encode(x))

        seriParams = pickle.dumps(encParams)#serialising

        sendBin(b'para' + seriParams, writer)
        sendBin(b'para' + seriParams, writer2)

        seri_enc_idp_pub = yield from reader2.readuntil(separator=b'fireinthepub')
        if seri_enc_idp_pub[0:4] == b'mypb':

            enc_idp_pub = pickle.loads(seri_enc_idp_pub[4:-12])
            list_enc_idp_pub = []
            for x in enc_idp_pub:
                list_enc_idp_pub.append(decode(x))

            idp_pub = tuple(list_enc_idp_pub)

        #encode and send user_commit to idp
        LT_user_state, user_commit = BL_user_setup(params, [10, 20])
        print(user_commit)

        encUserCommit = []

        for x in user_commit:
            encUserCommit.append(encode(x))

        seriUserCommit = pickle.dumps(encUserCommit)

        sendBin(b'ucmt' + seriUserCommit, writer2)

        msg2 = yield from reader2.readuntil(separator=b'fireintheboof')
        print(msg2)
        enc_msg_to_user = pickle.loads(msg2[:-13])
        list_msg_to_user = []
        for x in enc_msg_to_user:
            list_msg_to_user.append(decode(x))

        msg_to_user = tuple(list_msg_to_user)
        print(msg_to_user)

        BL_user_prep(LT_user_state, msg_to_user)

        #request idp's pubkey
        #sendBin(b'pubk', writer2)

        #inform idp Im prepped and ready to go
        sendBin(b'prep', writer2)

        msg3 = yield from reader2.readuntil(separator=b'fireintheboof')
        enc_msg_to_user2 = pickle.loads(msg3[:-13])
        list_msg_to_user2 = []
        for x in enc_msg_to_user2:
            list_msg_to_user2.append(decode(x))

        msg_to_user2 = tuple(list_msg_to_user2)

        #generate msg to idp
        msg_to_idp = BL_user_validation(LT_user_state, idp_pub, msg_to_user2)
        print('message to idp', type(msg_to_idp))

        #encode, serialise, and send msg to idp
        enc_msg_to_idp = encode(msg_to_idp)
        seri_enc_msg_to_idp = pickle.dumps(enc_msg_to_idp)
        sendBin(b'msgi' + seri_enc_msg_to_idp, writer2)

        #receive last message from idp, generate signature

        msg4 = yield from reader2.readuntil(separator=b'fireintheboof')
        enc_msg_to_user3 = pickle.loads(msg4[:-13])
        list_msg_to_user3 = []
        for x in enc_msg_to_user3:
            list_msg_to_user3.append(decode(x))

        msg_to_user3 = tuple(list_msg_to_user3)

        sig = BL_user_validation_2(LT_user_state, msg_to_user3)

        enc_sig = []
        for x in sig:
            enc_sig.append(encode(x))

        seri_enc_sig = pickle.dumps(enc_sig)
        sendBin(b'vsig' + seri_enc_sig + b'fireintheboof', writer)

        signature = BL_user_prove_cred(LT_user_state)

        enc_signature = []
        for x in signature:
            enc_signature.append(encode(x))

        seri_enc_signature = pickle.dumps(enc_signature)
        sendBin(b'vsg2' + seri_enc_signature + b'fireintheboof', writer)

        #Close the connections to get rid of IncompleteReadError



        cmd = "asd"
        #cmd, *args = msg2.rstrip().split(' ')
    if repr('IDCONFIRMED') == cmd:

        #for encryption
        """key = keyGen()
        print(repr(key))
        ciphertext = encrypt_AES(key, "HAUHEUheuahehaeuhUAEHUHEAUh")
        serialisedCiphertext = pickle.dumps(ciphertext)
        send(('key ' + repr(key)) + " " + repr(serialisedCiphertext), writer)"""
        """params = setup()
        G = params[0]

        C = EcPt.from_binary(literal_eval(args[0]), G)

        r = Bn.from_binary(literal_eval(args[1]))
        secrets = pickle.loads(literal_eval(args[2]))

        proof = proveCommitment(params, C, r, secrets)
        c, responses = proof
        #Here is where I send the proof to the service provider
        seriRes = pickle.dumps(responses)
        send('Proof ' + repr(c) + " " + repr(seriRes), writer)
        print("the end")"""
        end = time.time()
        print("Time: ", end-start)


    writer.close()
    writer2.close()


try:
    for _ in range(500):
        loop.run_until_complete(client())
finally:
    loop.close()

"""def main():
    for _ in range(10):
        try:
            loop.run_until_complete(client())
        finally:
            loop.close()

if __name__ == 'main':
    main()"""