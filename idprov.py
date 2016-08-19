import sys
import asyncio
import asyncio.streams

from petlib.ec import EcPt, EcGroup
from petlib.bn import Bn
from petlib.pack import encode, decode
import time

from hashlib import sha256
from binascii import hexlify

import encdec

from ast import literal_eval

loop = asyncio.get_event_loop()

peopleTestList = {'John':21, 'Nasos':22, 'Andreas':14, 'Tom':12, 'Anna':40, 'Maria':10}

class MyServer:

    def __init__(self):
        self.server = None

        self.clients = {} # task -> (reader, writer)

    def _accept_client(self, client_reader, client_writer):

        # start a new Task to handle this specific client connection
        task = asyncio.Task(self._handle_client(client_reader, client_writer))
        self.clients[task] = (client_reader, client_writer)

        def client_done(task):
            #print("client task done:", task, file=sys.stderr)
            del self.clients[task]

        task.add_done_callback(client_done)

    @asyncio.coroutine
    def _handle_client(self, client_reader, client_writer):

        global paramsReceived

        while True:
            try:  # data = (yield from client_reader.readline()).decode("utf-8")
                startWait = time.time()
                data = yield from client_reader.readuntil(separator=b'fireintheboof')
                endWait = time.time()
                print('IO wait: ', data[0:4], endWait - startWait)
                cmd = data[0:4]
                strippedData = data[4:-13]
            except asyncio.streams.IncompleteReadError:
                data = None
            if not data:  # an empty string means the client disconnected
                break
                # cmd, *args = str(data).rstrip().split(' ')
            if cmd == 'id':
                """secrets = [3, 645, 3430, 420]
                seriSecrets = pickle.dumps(secrets)
                params = setup()

                C, r = commit(params, secrets)
                G = params[0]

                exportedC = C.export()

                retval = 'IDCONFIRMED'

                #client_writer.write("{!r}\n".format(retval).encode("utf-8"))
                #Interesting asyncio thingy here, if I send the data to the client first, the proof is never correct
                #THe client completes and sends the proof to the service provider before the SP receives the C from here."""
                print(literal_eval(args[0]))
                print(type(literal_eval(args[0])))

                reader_sp, writer_sp = yield from asyncio.streams.open_connection("localhost", 12345, loop = loop)
                params = BL_setup()
                LT_idp_state, idp_pub = BL_idp_keys(params)
                #conv_user_commit = bytes(args[0], "utf8")
                #user_commit = encdec.decode(conv_user_commit)
                user_commit = encdec.decode(literal_eval(args[0]))
                msg_to_user = BL_idp_prep(LT_idp_state, user_commit)
            elif cmd == b'para':
                #reader_sp, writer_sp = yield from asyncio.streams.open_connection("localhost", 12345, loop=loop)
                start = time.time()
                paramsReceived = True
                print('Starting...')

                params = decode(strippedData)
                G, q, g, h, z, hs = params
                LT_idp_state, idp_pub = BL_idp_keys(params)


                #send public key to user and service provider

                #writer_sp.write(b'ipub' + encode(idp_pub) + b'fireintheboof')
                client_writer.write(b'mypb' + encode(idp_pub) + b'fireinthepub')


            elif cmd == b'ucmt':
                user_commit, C, c, responses, L2, Age = decode(strippedData)
                rR, rx = responses



                H = G.hash_to_point(b'service_name')
                ID = L2 * H

                Cprime = C - Age * hs[2]

                Wprime = rR * hs[0] + rx * hs[1] + c * Cprime

                Wxprime = rx * H + c * ID

                stuffToHash = (Wprime, Wxprime, C, g, h, z, hs[0], hs[1], hs[2], hs[3], H)
                cstr = b",".join([hexlify(x.export()) for x in stuffToHash])
                chash = sha256(cstr).digest()
                cprime = Bn.from_binary(chash)

                if c == cprime:
                    print("success")
                else:
                    print("no")





                #generate message to user
                msg_to_user = BL_idp_prep(LT_idp_state, user_commit)

                client_writer.write(encode(msg_to_user) + b'fireintheboof')

            elif cmd == b'prep':
                msg_to_user2 = BL_idp_validation(LT_idp_state)

                client_writer.write(encode(msg_to_user2) + b'fireintheboof')

            elif cmd == b'msgi':
                msg_to_idp = decode(strippedData)

                # generate 3rd message to user
                msg_to_user3 = BL_idp_validation_2(LT_idp_state, msg_to_idp)

                client_writer.write(encode(msg_to_user3) + b'fireintheboof')

                end = time.time()
                finalTime = end - start
                print('Total time taken: ', finalTime)

            else:
                #print("Bad command {!r}".format(data), file=sys.stderr)
                pass

            # This enables us to have flow control in our connection.
            yield from client_writer.drain()

    def start(self, loop):

        self.server = loop.run_until_complete(
            asyncio.streams.start_server(self._accept_client,
                                         '127.0.0.1', 7878,
                                         loop=loop))

    def stop(self, loop):

        if self.server is not None:
            self.server.close()
            loop.run_until_complete(self.server.wait_closed())
            self.server = None


def send(msg, writer):
        print("> " + msg)
        writer.write((msg + '\n').encode("utf-8"))


"""def setup():

    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(4)]
    o = G.order()
    return (G, g, hs, o)


def keyGen(params):

   (G, g, hs, o) = params
   priv = o.random()
   pub = priv * g
   return (priv, pub)


def to_challenge(elements):

    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)


def commit(params, secrets):

    assert len(secrets) == 4
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets
    r = o.random()
    C = x0 * h0 + x1 * h1 + x2 * h2 + x3 * h3 + r * g
    return (C, r)"""
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

def BL_idp_keys(params):
    (G, q, g, h, z, hs) = params

    x = q.random()
    y = x * g

    idp_state = StateHolder()
    idp_state.params = params
    idp_state.x = x
    idp_state.y = y

    return idp_state, (y, )

def BL_idp_prep(idp_state, user_commit):
    (G, q, g, h, z, hs) = idp_state.params
    (x, y) = (idp_state.x, idp_state.y)

    (C, ) = user_commit

    rnd = q.random()
    z1 = C + rnd * g
    z2 = z + (-z1)

    #send
    if rnd % q == 0:
        raise

    idp_state.rnd = rnd
    idp_state.z1 = z1
    idp_state.z2 = z2

    message_to_user = (rnd, )

    return message_to_user


def BL_idp_validation(idp_state):
    (G, q, g, h, z, hs) = idp_state.params

    u, r1p, r2p, cp = [q.random() for _ in range(4)]
    a = u * g
    a1p = r1p * g + cp * idp_state.z1
    a2p = r2p * h + cp * idp_state.z2

    idp_state.u = u
    idp_state.r1p = r1p
    idp_state.r2p = r2p
    idp_state.cp = cp

    return (a, a1p, a2p)

def BL_idp_validation_2(idp_state, msg_from_user):
    (G, q, g, h, z, hs) = idp_state.params
    # x, y = key_pair
    # (u, r1p, r2p, cp) = issuer_val_private
    e = msg_from_user

    ## Send: (e,) to Issuer
    c = e.mod_sub(idp_state.cp, q)
    r = idp_state.u.mod_sub((c * idp_state.x), q)

    msg_to_user = (c, r, idp_state.cp, idp_state.r1p, idp_state.r2p)
    return msg_to_user




def main():
    loop = asyncio.get_event_loop()
    future = asyncio.Future()

    global paramsReceived
    paramsReceived = False

    server = MyServer()
    server.start(loop)


    try:
        loop.run_until_complete(future)
        server.stop(loop)
    finally:
        loop.close()


if __name__ == '__main__':
    main()