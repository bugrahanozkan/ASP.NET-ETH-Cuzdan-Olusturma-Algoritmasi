using System;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

    public class WdrECKey
    {
        private static readonly SecureRandom SecureRandom = new SecureRandom();
        public static byte DEFAULT_PREFIX = 0x04;
        private readonly ECKey _ecKey;
        private byte[] _publicKey;
        private byte[] _publicKeyCompressed;
        private byte[] _publicKeyNoPrefix;
        private byte[] _publicKeyNoPrefixCompressed;
        private string _ethereumAddress;
        private byte[] _privateKey;
        private string _privateKeyHex;


        public WdrECKey(string privateKey)
        {
            _ecKey = new ECKey(privateKey.HexToByteArray(), true);
        }


        public WdrECKey(byte[] vch, bool isPrivate)
        {
            _ecKey = new ECKey(vch, isPrivate);
        }

        public WdrECKey(byte[] vch, bool isPrivate, byte prefix)
        {
            _ecKey = new ECKey(ByteUtil.Merge(new[] { prefix }, vch), isPrivate);
        }

        internal WdrECKey(ECKey ecKey)
        {
            _ecKey = ecKey;
        }


        public byte[] CalculateCommonSecret(WdrECKey publicKey)
        {
            var agreement = new ECDHBasicAgreement();
            agreement.Init(_ecKey.PrivateKey);
            var z = agreement.CalculateAgreement(publicKey._ecKey.GetPublicKeyParameters());

            return BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), z);
        }

        //Note: Y coordinates can only be forced, so it is assumed 0 and 1 will be the recId (even if implementation allows for 2 and 3)
        internal int CalculateRecId(ECDSASignature signature, byte[] hash)
        {
            var thisKey = _ecKey.GetPubKey(false); // compressed
            return CalculateRecId(signature, hash, thisKey);
        }

        internal static int CalculateRecId(ECDSASignature signature, byte[] hash, byte[] uncompressedPublicKey)
        {
            var recId = -1;

            for (var i = 0; i < 4; i++)
            {
                var rec = ECKey.RecoverFromSignature(i, signature, hash, false);
                if (rec != null)
                {
                    var k = rec.GetPubKey(false);
                    if (k != null && k.SequenceEqual(uncompressedPublicKey))
                    {
                        recId = i;
                        break;
                    }
                }
            }
            if (recId == -1)
                throw new Exception("Could not construct a recoverable key. This should never happen.");
            return recId;
        }

        public static WdrECKey GenerateKey(byte[] seed = null)
        {
            var secureRandom = SecureRandom;
            if (seed != null)
            {
                secureRandom = new SecureRandom();
                secureRandom.SetSeed(seed);
            }

            var gen = new ECKeyPairGenerator("EC");
            var keyGenParam = new KeyGenerationParameters(secureRandom, 256);
            gen.Init(keyGenParam);
            var keyPair = gen.GenerateKeyPair();
            var privateBytes = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray();
            if (privateBytes.Length != 32)
                return GenerateKey();
            return new WdrECKey(privateBytes, true);
        }

        public static WdrECKey GenerateKey()
        {
            var gen = new ECKeyPairGenerator("EC");
            var keyGenParam = new KeyGenerationParameters(SecureRandom, 256);
            gen.Init(keyGenParam);
            var keyPair = gen.GenerateKeyPair();
            var privateBytes = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray();
            if (privateBytes.Length != 32)
                return GenerateKey();
            return new WdrECKey(privateBytes, true);
        }

        public byte[] GetPrivateKeyAsBytes()
        {
            if (_privateKey == null)
            {
                _privateKey = _ecKey.PrivateKey.D.ToByteArrayUnsigned();
            }
            return _privateKey;
        }

        public string GetPrivateKey()
        {
            if (_privateKeyHex == null)
            {
                _privateKeyHex = GetPrivateKeyAsBytes().ToHex(true);
            }
            return _privateKeyHex;
        }

        public byte[] GetPubKey(bool compresseed = false)
        {
            if (!compresseed)
            {
                if (_publicKey == null)
                {
                    _publicKey = _ecKey.GetPubKey(false);
                }
                return _publicKey;
            }
            else
            {
                if (_publicKeyCompressed == null)
                {
                    _publicKeyCompressed = _ecKey.GetPubKey(true);
                }
                return _publicKeyCompressed;

            }
        }

        public byte[] GetPubKeyNoPrefix(bool compressed = false)
        {
            if (!compressed)
            {
                if (_publicKeyNoPrefix == null)
                {
                    var pubKey = _ecKey.GetPubKey(false);
                    var arr = new byte[pubKey.Length - 1];
                    //remove the prefix
                    Array.Copy(pubKey, 1, arr, 0, arr.Length);
                    _publicKeyNoPrefix = arr;
                }
                return _publicKeyNoPrefix;
            }
            else
            {
                if (_publicKeyNoPrefixCompressed == null)
                {
                    var pubKey = _ecKey.GetPubKey(true);
                    var arr = new byte[pubKey.Length - 1];
                    //remove the prefix
                    Array.Copy(pubKey, 1, arr, 0, arr.Length);
                    _publicKeyNoPrefixCompressed = arr;
                }
                return _publicKeyNoPrefixCompressed;

            }
        }

        public string GetPublicAddress()
        {
            if (_ethereumAddress == null)
            {
                var initaddr = new Sha3Keccack().CalculateHash(GetPubKeyNoPrefix());
                var addr = new byte[initaddr.Length - 12];
                Array.Copy(initaddr, 12, addr, 0, initaddr.Length - 12);
                _ethereumAddress = new AddressUtil().ConvertToChecksumAddress(addr.ToHex());
            }
            return _ethereumAddress;
        }

        public static string GetPublicAddress(string privateKey)
        {
            var key = new WdrECKey(privateKey.HexToByteArray(), true);
            return key.GetPublicAddress();
        }

        public static int GetRecIdFromV(byte[] v)
        {
            return GetRecIdFromV(v[0]);
        }


        public static int GetRecIdFromV(byte v)
        {
            var header = v;
            // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
            //                  0x1D = second key with even y, 0x1E = second key with odd y
            if (header < 27 || header > 34)
                throw new Exception("Header byte out of range: " + header);
            if (header >= 31)
                header -= 4;
            return header - 27;
        }

       
}
