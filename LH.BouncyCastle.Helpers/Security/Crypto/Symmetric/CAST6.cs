﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// CAST6.
    /// <para/>Legal block size 128 bits. Legal key size 128-256 bits (8 bits increments).
    /// </summary>
    public sealed class CAST6 : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 256, 8) };



        #endregion Properties

        #region Constructor

        /// <summary>
        /// CAST6.
        /// <para/>Legal block size 128 bits. Legal key size 128-256 bits (8 bits increments).
        /// </summary>
        public CAST6() : base("CAST6", _blockSizes, 128, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new Cast6Engine();
        }
    }
}