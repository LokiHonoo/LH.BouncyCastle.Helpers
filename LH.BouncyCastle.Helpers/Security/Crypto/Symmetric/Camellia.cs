﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Camellia.
    /// <para/>Legal block size 128 bits. Legal key size 128, 192, 256 bits.
    /// </summary>
    public sealed class Camellia : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 256, 64) };


        #endregion Properties

        #region Constructor

        /// <summary>
        /// Camellia.
        /// <para/>Legal block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public Camellia() : base("Camellia", _blockSizes, 128, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new CamelliaLightEngine();
        }
    }
}