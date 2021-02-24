﻿namespace LH.BouncyCastle.Helpers
{
    /// <summary>
    /// X509Extension label.
    /// </summary>
    public enum X509ExtensionLabel
    {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释

        AuditIdentity = 1, AuthorityInfoAccess, AuthorityKeyIdentifier,
        BasicConstraints, BiometricInfo,
        CertificateIssuer, CertificatePolicies, CrlDistributionPoints, CrlNumber,
        DeltaCrlIndicator,
        ExpiredCertsOnCrl, ExtendedKeyUsage,
        FreshestCrl,
        InhibitAnyPolicy, InstructionCode, InvalidityDate, IssuerAlternativeName, IssuingDistributionPoint,
        KeyUsage,
        LogoType,
        NameConstraints, NoRevAvail,
        PolicyConstraints, PolicyMappings, PrivateKeyUsagePeriod,
        QCStatements,
        ReasonCode,
        SubjectAlternativeName, SubjectDirectoryAttributes, SubjectInfoAccess, SubjectKeyIdentifier,
        TargetInformation,

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}