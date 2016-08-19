import asyncio
import asyncio.streams
import sys
import subprocess
import petlib
from os import urandom
from petlib.cipher import Cipher
import pickle
from ast import literal_eval

from petlib.hmac import Hmac

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



class StateHolder(object):
    pass

def BL_setup(Gid = 713):
    G = EcGroup(Gid)
    q = G.order()

    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    z = G.hash_to_point(b"z")
    hs = [G.hash_to_point(("h%s" % i).encode("utf-8")) for i in range(4)]#what is this

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
    return zk#we need to send this to the SP

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
    env.gamg = gam_g = user_state.gam * g
    env.gamhs = gam_hs = [user_state.gam * hsi for hsi in hs[:len(user_state.attributes) + 1]]

    ## Extract the proof
    sig = zk.build_proof(env.get())
    if __debug__:
        assert zk.verify_proof(env.get(), sig, strict=False)

    return sig, gam_hs, gam_g

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
        #print("bin>" + str(data))
        writer.write(data + b'fireintheboof')
        #writer.write_eof()

    def recv(reader):
        msgback = (yield from reader.readline()).decode("utf-8").rstrip()
        #print("< " + msgback)
        return msgback

    # send a line
    #send("buy", writer)
    sendBin(b'buys', writer)
    msg = yield from recv(reader)
    #if repr('id') == msg:
    if True:
        startWait = time.time()
        print("ok i go get ID")

        #generating, encoding, and sending parameters to both sp and idp
        params = BL_setup()

        G, q, g, h, z, hs = params

        endWait = time.time()

        sendBin(b'para' + encode(params), writer)
        sendBin(b'para' + encode(params), writer2)


        print('Time to generate params: ', endWait-startWait)

        seri_enc_idp_pub = yield from reader2.readuntil(separator=b'fireinthepub')
        if seri_enc_idp_pub[0:4] == b'mypb':



            #idp_pub = tuple(list_enc_idp_pub)
            idp_pub = decode(seri_enc_idp_pub[4:-12])
            sendBin(b'ipub' + encode(idp_pub) + b'fireintheboof', writer)

        #h = Hmac(b'sha256', b'ServiceProviderID')

        L2 = q.random()
        Age = 21

        #new
        #N = params[0].hash_to_point('service_name')
        #pseudonym = x * N

        #encode and send user_commit to idp
        LT_user_state, user_commit = BL_user_setup(params, [L2, Age])

        startTimeProof = time.time()

        C = LT_user_state.C
        R = LT_user_state.R
        q = LT_user_state.params[1]
        H = params[0].hash_to_point(b'service_name')
        ID = L2 * H

        wR_id = q.random()
        wx_id = q.random()

        Wit = wR_id * hs[0] + wx_id * hs[1]
        WID_id = wx_id * H

        print(hs)

        stuffToHash = (Wit, WID_id, C, g, h, z, hs[0], hs[1], hs[2], hs[3], H)
        cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
        chash = sha256(cstr).digest()
        c = Bn.from_binary(chash)

        rR_id = wR_id - c * R
        rx_id = wx_id - c * L2

        endTimeProof = time.time()
        print('Proof took: ', endTimeProof - startTimeProof)

        responses = (rR_id, rx_id)

        values = (user_commit, C, c, responses, L2, Age)

        sendBin(b'ucmt' + encode(values), writer2)

        msg2 = yield from reader2.readuntil(separator=b'fireintheboof')

        msg_to_user = decode(msg2[:-13])

        BL_user_prep(LT_user_state, msg_to_user)

        #request idp's pubkey
        #sendBin(b'pubk', writer2)

        #inform idp Im prepped and ready to go
        sendBin(b'prep', writer2)

        msg3 = yield from reader2.readuntil(separator=b'fireintheboof')

        msg_to_user2 = decode(msg3[:-13])

        #generate msg to idp
        msg_to_idp = BL_user_validation(LT_user_state, idp_pub, msg_to_user2)

        #encode, serialise, and send msg to idp
        sendBin(b'msgi' + encode(msg_to_idp), writer2)

        #receive last message from idp, generate signature

        msg4 = yield from reader2.readuntil(separator=b'fireintheboof')

        msg_to_user3 = decode(msg4[:-13])

        sig = BL_user_validation_2(LT_user_state, msg_to_user3)


        sendBin(b'vsig' + encode(sig) + b'fireintheboof', writer)

        print('idppub: ', idp_pub)

        signature_gamhs = BL_user_prove_cred(LT_user_state)
        signature = signature_gamhs[0]
        gam_hs = signature_gamhs[1]
        gam_g = signature_gamhs[2]


        sendBin(b'vsg2' + encode(signature) + b'fireintheboof', writer)

        zet1p = LT_user_state.zet1 - Age * gam_hs[2]
        newStuff = (gam_hs, Age)

        #prove age

        #get variabels
        rnd = LT_user_state.rnd
        R = LT_user_state.R
        q = LT_user_state.params[1]


        wrnd = q.random()
        wR = q.random()
        wx = q.random()

        Wzet1p = wrnd * gam_g + wR * gam_hs[0] + wx * gam_hs[1] #remember to get gam_g

        WID = wx * params[0].hash_to_point(b'service_name')

        stuffToHash = (gam_g, Wzet1p, WID, zet1p, gam_hs[0], gam_hs[1], gam_hs[2], H)
        cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
        chash = sha256(cstr).digest()
        c = Bn.from_binary(chash)

        rrnd = wrnd - c*rnd
        rR = wR - c*R
        rx = wx - c*L2

        responses = (rrnd, rR, rx)
        newStuff = (c, responses, gam_g, gam_hs, Age, L2)

        """Wprime = rrnd * gam_g + rR * gam_hs[0] + rx * gam_hs[1] + c * zet1p

        print(Wzet1p)
        print(Wprime)"""


        sendBin(b'page' + encode(newStuff) + b'fireintheboof', writer)

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