﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// VMPC.
    /// <para/>Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
    /// </summary>
    public sealed class VMPC : StreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(8, 6144, 8) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(256, 256, 0) };


        #endregion Properties

        #region Constructor

        /// <summary>
        /// VMPC.
        /// <para/>Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
        /// </summary>
        public VMPC() : base("VMPC", _keySizes, _ivSizes)
        {
        }

        #endregion Constructor

        private protected override IStreamCipher GenerateEngine()
        {
            return new VmpcEngine();
        }
    }
}