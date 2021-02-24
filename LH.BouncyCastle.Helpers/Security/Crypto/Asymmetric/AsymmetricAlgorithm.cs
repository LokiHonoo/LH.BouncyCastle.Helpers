using Org.BouncyCastle.Crypto;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric algorithm.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// SM2.
        /// </summary>
        private protected AsymmetricAlgorithm(string mechanism)
        {
            this.Mechanism = mechanism;
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public abstract AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.Mechanism;
        }
    }
}