﻿using Org.BouncyCastle.Crypto;

namespace LH.BouncyCastle.Helpers
{
    /// <summary>
    /// Hash algorithm interface.
    /// </summary>
    public interface IHashAlgorithm
    {
        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        int HashSize { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        byte[] ComputeHash(byte[] data);

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] ComputeHash(byte[] data, int offset, int length);

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        IDigest GenerateDigest();

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}