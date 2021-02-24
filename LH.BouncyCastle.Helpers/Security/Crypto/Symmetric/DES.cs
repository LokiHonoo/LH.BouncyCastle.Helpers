using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// DES.
    /// <para/>Legal block size 64 bits. Legal key size 64 bits.
    /// </summary>
    public sealed class DES : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(64, 64, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// DES.
        /// <para/>Legal block size 64 bits. Legal key size 64 bits.
        /// </summary>
        public DES() : base("DES", _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new DesEngine();
        }

        private protected override KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new DesParameters(key);
        }

        private protected override KeyParameter GenerateKeyParameter(byte[] key, int offset, int length)
        {
            return new DesParameters(key, offset, length);
        }
    }
}