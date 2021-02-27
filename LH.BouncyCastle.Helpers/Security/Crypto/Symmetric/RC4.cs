﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// RC4, ARC4.
    /// <para/>Legal key size 256 bits. Not need IV.
    /// </summary>
    public sealed class RC4 : StreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(0, 0, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(256, 256, 0) };



        #endregion Properties

        #region Constructor

        /// <summary>
        /// RC4, ARC4.
        /// <para/>Legal key size 256 bits. Not need IV.
        /// </summary>
        public RC4() : base("RC4", _keySizes, _ivSizes)
        {
        }

        #endregion Constructor

        private protected override IStreamCipher GenerateEngine()
        {
            return new RC4Engine();
        }
    }
}