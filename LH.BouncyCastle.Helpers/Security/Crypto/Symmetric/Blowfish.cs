﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Blowfish.
    /// <para/>Legal block size 64 bits. Legal key size 128 bits.
    /// </summary>
    public sealed class Blowfish : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 128, 0) };



        #endregion Properties

        #region Constructor

        /// <summary>
        /// Blowfish.
        /// <para/>Legal block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public Blowfish() : base("Blowfish", _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new BlowfishEngine();
        }
    }
}