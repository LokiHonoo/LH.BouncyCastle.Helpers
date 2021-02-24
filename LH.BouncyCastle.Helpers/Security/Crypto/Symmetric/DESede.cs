using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// DESede, DESede3, TDEA, TripleDES, 3DES.
    /// <para/>Legal block size 64 bits. Legal key size 128, 192 bits.
    /// </summary>
    public sealed class DESede : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 192, 64) };



        #endregion Properties

        #region Constructor

        /// <summary>
        /// DESede, DESede3, TDEA, TripleDES, 3DES.
        /// <para/>Legal block size 64 bits. Legal key size 128, 192 bits.
        /// </summary>
        public DESede() : base("DESede", _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new DesEdeEngine();
        }

        private protected override KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new DesEdeParameters(key);
        }

        private protected override KeyParameter GenerateKeyParameter(byte[] key, int offset, int length)
        {
            return new DesEdeParameters(key, offset, length);
        }
    }
}