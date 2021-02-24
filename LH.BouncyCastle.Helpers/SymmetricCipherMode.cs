﻿namespace LH.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm cipher mode.
    /// </summary>
    public enum SymmetricCipherMode
    {
        /// <summary>
        /// IV size is same as block size.
        /// </summary>
        CBC = 1,

        /// <summary>
        /// Not need IV.
        /// </summary>
        ECB,

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        OFB,

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        CFB,

        /// <summary>
        /// IV size is same as block size.
        /// <para/>CTS cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        CTS,

        /// <summary>
        /// The minimum IV size is the larger of (block size / 2) and (block size - 64) bits. The maximum iv size is is same as block size. 8 bits increments.
        /// </summary>
        CTR = 101,

        /// <summary>
        /// Not need IV.
        /// <para/>CTS cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        CTS_ECB,

        /// <summary>
        /// IV size is same as block size.
        /// <para/>GOFB cipher mode uses with a block size of 64 bits algorithm (e.g. DESede).
        /// </summary>
        GOFB,

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        OpenPGPCFB,

        /// <summary>
        /// The minimum IV size is the larger of (block size / 2) and (block size - 64) bits. The maximum iv size is is same as block size. 8 bits increments.
        /// <para/>SIC cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// </summary>
        SIC,

        /// <summary>
        /// Nonce size 56-104 bits (8 bits increments). MAC size 32-128 bits (16 bits increments).
        /// <para/>CCM cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// <para/>CCM cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        CCM = 201,

        /// <summary>
        /// Nonce size is more than or equal to 8 bits (8 bits increments). MAC size is between 8 and block size (8 bits increments).
        /// <para/>EAX cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).
        /// <para/>EAX cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        EAX,

        /// <summary>
        /// Nonce size is more than or equal to 8 bits (8 bits increments). MAC size 32-128 bits (8 bits increments).
        /// <para/>GCM cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).
        /// <para/>GCM cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// <para/>Warning: GCM cipher mode cannot be reused. The cipher instance needs to be recreated every time. (BouncyCastle 1.8.9).
        /// </summary>
        GCM,

        /// <summary>
        /// Nonce size is null or less than 120 bits (8 bits increments). MAC size 64-128 bits (8 bits increments).
        /// <para/>OCB cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// <para/>OCB cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        OCB,
    }
}