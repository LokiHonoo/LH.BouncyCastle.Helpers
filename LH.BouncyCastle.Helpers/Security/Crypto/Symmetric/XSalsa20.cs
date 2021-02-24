﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// XSalsa20.
    /// <para/>Legal key size 256 bits. Legal iv size 192 bits.
    /// </summary>
    public sealed class XSalsa20 : StreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(192, 192, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// XSalsa20.
        /// <para/>Legal key size 256 bits. Legal iv size 192 bits.
        /// </summary>
        public XSalsa20() : base("XSalsa20", _keySizes, _ivSizes)
        {
        }

        #endregion Constructor

        private protected override IStreamCipher GenerateEngine()
        {
            return new XSalsa20Engine();
        }
    }
}