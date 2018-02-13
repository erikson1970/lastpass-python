# coding: utf-8
from . import fetcher
from . import parser
from .exceptions import InvalidResponseError


class Vault(object):
    @classmethod
    def open_remote(cls, username, password, multifactor_password=None, client_id=None,blob_filename=None):
        """Fetches a blob from the server and creates a vault"""
        blob = cls.fetch_blob(username, password, multifactor_password, client_id,blob_filename)
        print "open_remote:"
        return cls.open(blob, username, password)

    @classmethod
    def open_local(cls, username, password,blob_filename):
        """Creates a vault from a locally stored blob"""
        blob=readblob_local(username,password,blob_filename)
        raise cls.open(blob,username,password)

    @classmethod
    def open(cls, blob, username, password):
        """Creates a vault from a blob object"""
        return cls(blob, blob.encryption_key(username, password))

    @classmethod
    def fetch_blob(cls, username, password, multifactor_password=None, client_id=None,blob_filename=None):
        """Just fetches the blob, could be used to store it locally"""
        session = fetcher.login(username, password, multifactor_password, client_id)
        blob = fetcher.fetch(session)
        fetcher.logout(session)
        if blob_filename:
            cls.writeblob_local(blob,username,password,blob_filename)

        return blob

    @classmethod  
    def readblob_local(cls,newusername,passwordIn,filename='LPBlob.bin'):
        """Read and decode a blob from a local file """
        with open(filename, 'r') as myfile:
            filedatain=myfile.read().replace('\n', '').strip()
        newusername=filedatain[4:104].strip()
        mydecodingkey=fetcher.make_key(newusername,passwordIn,10)
        innerdecoded=parser.decode_aes256_cbc_base64(filedatain[105:],mydecodingkey)
        my_IterCountIn=int(innerdecoded[1:17])
        mydecodingkey=fetcher.make_key(newusername,passwordIn,my_IterCountIn)
        decoded=parser.decompress(parser.decode_aes256_cbc_base64(innerdecoded[17:],mydecodingkey))
        newblob=fetcher.blob.Blob(decoded,my_IterCountIn)
        return newblob


    @classmethod
    def writeblob_local(cls,myblob,username,password,filename='LPBlob.bin'):
        """write a blob to a local file"""
        mykey=fetcher.make_key(username,password,myblob.key_iteration_count)
        myiv="\x00"+parser.urandom(14)+"\x00"
        innerencoded="#%16d%s"%(myblob.key_iteration_count,parser.encode_aes256_cbc_base64(parser.compress(myblob.bytes),mykey,myiv))
        myiv="\x00"+parser.urandom(14)+"\x00"
        mykey=fetcher.make_key(username,password,10)
        filedata="BLOB%100s#%s"%(username,parser.encode_aes256_cbc_base64(innerencoded,mykey,myiv))
        with open(filename,'w') as fp:
            fp.write(filedata)

        
    def __init__(self, blob, encryption_key):
        """This more of an internal method, use one of the static constructors instead"""
        chunks = parser.extract_chunks(blob)

        if not self.is_complete(chunks):
            raise InvalidResponseError('Blob is truncated')

        self.accounts = self.parse_accounts(chunks, encryption_key)

    def is_complete(self, chunks):
        return len(chunks) > 0 and chunks[-1].id == b'ENDM' and chunks[-1].payload == b'OK'

    def parse_accounts(self, chunks, encryption_key):
        accounts = []

        key = encryption_key
        rsa_private_key = None

        for i in chunks:
            if i.id == b'ACCT':
                # TODO: Put shared folder name as group in the account
                account = parser.parse_ACCT(i, key)
                if account:
                    accounts.append(account)
            elif i.id == b'PRIK':
                rsa_private_key = parser.parse_PRIK(i, encryption_key)
            elif i.id == b'SHAR':
                # After SHAR chunk all the folliwing accounts are enrypted with a new key
                key = parser.parse_SHAR(i, encryption_key, rsa_private_key)['encryption_key']

        return accounts
