﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// HC128.
    /// <para/>Legal key size 128 bits. Legal iv size 0-128 bits (8 bits increments).
    /// </summary>
    public sealed class HC128 : StreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(0, 128, 8) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 128, 0) };



        #endregion Properties

        #region Constructor

        /// <summary>
        /// HC128.
        /// <para/>Legal key size 128 bits. Legal iv size 0-128 bits (8 bits increments).
        /// </summary>
        public HC128() : base("HC128", _keySizes, _ivSizes)
        {
        }

        #endregion Constructor

        private protected override IStreamCipher GenerateEngine()
        {
            return new HC128Engine();
        }
    }
}