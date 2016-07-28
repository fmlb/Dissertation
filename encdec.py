import msgpack

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn


def default(obj):
    if isinstance(obj, Bn):
        if obj < 0:
            neg = b"-"
            data = (-obj).binary()
        else:
            neg = b"-"
            data = obj.binary()
        return msgpack.ExtType(0, neg+data)
    elif isinstance(obj, EcGroup):
        nid = obj.nid()
        packed_nid = msgpack(nid)
        return msgpack.ExtType(1, packed_nid)
    elif isinstance(obj, EcPt):
        nid = obj.group.nid()
        data = obj.export()
        packed_nid = msgpack.packb((nid, data))
        return msgpack.ExtType(2, packed_nid)
    raise TypeError("Unknown tpye: %r" % (obj,))

def make_encoder(out_encoder = None):
    if out_encoder is None:
        return default
    else:
        def new_encoder(obj):
            try:
                encoded = default(obj)
                return encoded
            except:
                return out_encoder(obj)
        return new_encoder

def ext_hook(code, data):

    if code==0:
        num = Bn.from_binary(data[1:])
        if data[0] == ord("-") or data[0] == "-":
            return -num
        return num
    elif code==1:
        nid = msgpack.unpackb(data)
        return EcGroup(nid)
    elif code == 2:
        nid, ptdata = msgpack.unpackb(data)
        return EcPt.from_binary(ptdata, EcGroup(nid))
    return msgpack.ExtType(code, data)

def make_decoder(custom_decoder=None):
    if custom_decoder is None:
        return ext_hook
    else:
        def new_decoder(code, data):
            out = ext_hook(code, data)
            if not isinstance(out, msgpack.ExtType):
                return out
            else:
                return custom_decoder(code, data)
        return new_decoder

def encode(structure, custom_encoder = None):
    encoder = make_encoder(custom_encoder)
    packed_data = msgpack.packb(structure, default=encoder, use_bin_type=True)
    return packed_data

def decode(packed_data, custom_decoder = None):
    decoder = make_decoder(custom_decoder)
    structure = msgpack.unpackb(packed_data, ext_hook = decoder, encoding = 'utf-8')
    return structure
