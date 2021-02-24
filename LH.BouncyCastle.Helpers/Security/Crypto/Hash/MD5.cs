﻿using LH.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// MD5.
    /// <para/>Legal hash size 128 bits.
    /// </summary>
    public sealed class MD5 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(128, 128, 0) };


        #endregion Properties

        #region Constructor

        /// <summary>
        /// MD5.
        /// <para/>Legal hash size 128 bits.
        /// </summary>
        public MD5() : base("MD5", _hashSizes    ,128)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new MD5Digest();
        }


    }
}