﻿using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers
{
    /// <summary>
    /// CMAC  interface.
    /// </summary>
    public interface ICMAC
    {
        /// <summary>
        /// Gets block size bits.
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        int HashSize { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        KeySizes[] KeySizes { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IMac GenerateDigest(ICipherParameters parameters);

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key);

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key, int offset, int length);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}