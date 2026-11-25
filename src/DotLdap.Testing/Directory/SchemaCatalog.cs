namespace DotLdap.Testing;

/// <summary>
/// How the values of an attribute are to be read. The server stores bytes; the syntax is what the published
/// schema tells clients that need one. ADSI (System.DirectoryServices), for instance, turns <see cref="Integer"/>
/// into an int and <see cref="OctetString"/> into a byte array. The server itself takes two things from it: a
/// server-side sort compares <see cref="Integer"/> and <see cref="LargeInteger"/> as numbers, and with
/// <see cref="InMemoryDirectory.SchemaChecks"/> on, a client cannot write a value that does not fit.
/// </summary>
public enum AttributeSyntax
{
    /// <summary>UTF-8 text compared ignoring case; the default for attributes the server does not know.</summary>
    DirectoryString,
    /// <summary>A distinguished name, compared as one.</summary>
    DistinguishedName,
    /// <summary>A whole number, written in decimal.</summary>
    Integer,

    /// <summary>A 64-bit number, as Active Directory uses for pwdLastSet or accountExpires.</summary>
    LargeInteger,
    /// <summary><c>TRUE</c> or <c>FALSE</c>.</summary>
    Boolean,
    /// <summary>A time such as <c>20261125190000Z</c> (RFC 4517).</summary>
    GeneralizedTime,
    /// <summary>A time with a two-digit year, such as <c>261125190000Z</c>.</summary>
    UtcTime,
    /// <summary>Bytes with no text meaning, such as objectGUID or a photo.</summary>
    OctetString,
    /// <summary>An object identifier or a schema name, such as an objectClass value.</summary>
    Oid,
    /// <summary>ASCII text, such as mail.</summary>
    IA5String,
    /// <summary>Text of the printable character set (letters, digits, a few punctuation marks).</summary>
    PrintableString,
    /// <summary>Digits and spaces.</summary>
    NumericString,

    /// <summary>Active Directory's case-insensitive (teletex) string.</summary>
    CaseIgnoreString,

    /// <summary>Active Directory's case-sensitive string.</summary>
    CaseExactString,

    /// <summary>A Windows security descriptor (nTSecurityDescriptor).</summary>
    SecurityDescriptor,

    /// <summary>Active Directory's DN with a binary part (wellKnownObjects).</summary>
    DnWithBinary,

    /// <summary>Active Directory's DN with a string part.</summary>
    DnWithString,
}

/// <summary>One attribute type of the published schema.</summary>
/// <param name="Name">The attribute name.</param>
/// <param name="Oid">Its object identifier.</param>
/// <param name="Syntax">How its values are read.</param>
/// <param name="SingleValued">True when an entry may have one value at most.</param>
/// <param name="Operational">Returned only when asked for by name or with "+".</param>
/// <param name="UserModifiable">An operational attribute a client may write (the schema definitions themselves).</param>
internal sealed record AttributeType(string Name, string Oid, AttributeSyntax Syntax, bool SingleValued, bool Operational = false, bool UserModifiable = false);

/// <summary>One object class of the published schema. Kind is STRUCTURAL, ABSTRACT or AUXILIARY.</summary>
internal sealed record ObjectClassType(string Name, string Oid, string? Superior, string Kind);

/// <summary>
/// The attribute types and object classes the server knows by name. They exist so that the schema the server
/// publishes gives well-known attributes their real ids and syntaxes; writes are held against the attribute
/// types only when <see cref="InMemoryDirectory.SchemaChecks"/> is on.
/// </summary>
internal static class SchemaCatalog
{
    private const string MicrosoftArc = "1.2.840.113556.";

    // name, id, syntax, "1" when single-valued. Ids, syntaxes and the single-valued flag are the ones of the
    // Active Directory schema; the selection is this library's.
    private const string ActiveDirectoryAttributes = """
        cn 2.5.4.3 S 1; name 1.2.840.113556.1.4.1 S 1; distinguishedName 2.5.4.49 DN 1; objectClass 2.5.4.0 OID; objectCategory 1.2.840.113556.1.4.782 DN 1;
        objectGUID 1.2.840.113556.1.4.2 O 1; objectSid 1.2.840.113556.1.4.146 O 1; sIDHistory 1.2.840.113556.1.4.609 O;
        instanceType 1.2.840.113556.1.2.1 I 1; whenCreated 1.2.840.113556.1.2.2 T 1; whenChanged 1.2.840.113556.1.2.3 T 1;
        uSNCreated 1.2.840.113556.1.2.19 I8 1; uSNChanged 1.2.840.113556.1.2.120 I8 1; description 2.5.4.13 S; displayName 1.2.840.113556.1.2.13 S 1;
        displayNamePrintable 1.2.840.113556.1.2.353 PR 1; adminDescription 1.2.840.113556.1.2.226 S 1; adminDisplayName 1.2.840.113556.1.2.194 S 1;
        isCriticalSystemObject 1.2.840.113556.1.4.868 B 1; showInAdvancedViewOnly 1.2.840.113556.1.2.169 B 1; systemFlags 1.2.840.113556.1.4.375 I 1;
        nTSecurityDescriptor 1.2.840.113556.1.2.281 SD 1; isDeleted 1.2.840.113556.1.2.48 B 1; createTimeStamp 2.5.18.1 T 1; modifyTimeStamp 2.5.18.2 T 1;
        subSchemaSubEntry 2.5.18.10 DN; canonicalName 1.2.840.113556.1.4.916 S; sAMAccountName 1.2.840.113556.1.4.221 S 1;
        sAMAccountType 1.2.840.113556.1.4.302 I 1; userPrincipalName 1.2.840.113556.1.4.656 S 1; userAccountControl 1.2.840.113556.1.4.8 I 1;
        msDS-User-Account-Control-Computed 1.2.840.113556.1.4.1460 I 1; pwdLastSet 1.2.840.113556.1.4.96 I8 1; accountExpires 1.2.840.113556.1.4.159 I8 1;
        lockoutTime 1.2.840.113556.1.4.662 I8 1; badPwdCount 1.2.840.113556.1.4.12 I 1; badPasswordTime 1.2.840.113556.1.4.49 I8 1;
        lastLogon 1.2.840.113556.1.4.52 I8 1; lastLogoff 1.2.840.113556.1.4.51 I8 1; lastLogonTimestamp 1.2.840.113556.1.4.1696 I8 1;
        logonCount 1.2.840.113556.1.4.169 I 1; logonHours 1.2.840.113556.1.4.64 O 1; userWorkstations 1.2.840.113556.1.4.86 S 1;
        primaryGroupID 1.2.840.113556.1.4.98 I 1; memberOf 1.2.840.113556.1.2.102 DN; unicodePwd 1.2.840.113556.1.4.90 O 1; userPassword 2.5.4.35 O;
        servicePrincipalName 1.2.840.113556.1.4.771 S; adminCount 1.2.840.113556.1.4.150 I 1; scriptPath 1.2.840.113556.1.4.62 S 1;
        profilePath 1.2.840.113556.1.4.139 S 1; homeDirectory 1.2.840.113556.1.4.44 S 1; homeDrive 1.2.840.113556.1.4.45 S 1;
        userParameters 1.2.840.113556.1.4.138 S 1; codePage 1.2.840.113556.1.4.16 I 1; countryCode 1.2.840.113556.1.4.25 I 1;
        tokenGroups 1.2.840.113556.1.4.1301 O; tokenGroupsGlobalAndUniversal 1.2.840.113556.1.4.1418 O; primaryGroupToken 1.2.840.113556.1.4.1412 I 1;
        msDS-UserPasswordExpiryTimeComputed 1.2.840.113556.1.4.1996 I8 1; userCertificate 2.5.4.36 O; altSecurityIdentities 1.2.840.113556.1.4.867 S;
        msDS-SupportedEncryptionTypes 1.2.840.113556.1.4.1963 I 1; msDS-PrincipalName 1.2.840.113556.1.4.1865 S 1; givenName 2.5.4.42 S 1; sn 2.5.4.4 S 1;
        initials 2.5.4.43 S 1; middleName 2.16.840.1.113730.3.1.34 S 1; personalTitle 1.2.840.113556.1.2.615 S 1; generationQualifier 2.5.4.44 S 1;
        title 2.5.4.12 S 1; department 1.2.840.113556.1.2.141 S 1; company 1.2.840.113556.1.2.146 S 1; division 1.2.840.113556.1.4.261 S 1;
        employeeID 1.2.840.113556.1.4.35 S 1; employeeNumber 1.2.840.113556.1.2.610 S 1; employeeType 1.2.840.113556.1.2.613 S 1;
        manager 0.9.2342.19200300.100.1.10 DN 1; directReports 1.2.840.113556.1.2.436 DN; physicalDeliveryOfficeName 2.5.4.19 S 1;
        roomNumber 0.9.2342.19200300.100.1.6 S; streetAddress 1.2.840.113556.1.2.256 S 1; street 2.5.4.9 S 1; postOfficeBox 2.5.4.18 S; l 2.5.4.7 S 1;
        st 2.5.4.8 S 1; postalCode 2.5.4.17 S 1; c 2.5.4.6 S 1; co 1.2.840.113556.1.2.131 S 1; mail 0.9.2342.19200300.100.1.3 S 1;
        proxyAddresses 1.2.840.113556.1.2.210 S; legacyExchangeDN 1.2.840.113556.1.4.655 CI 1; telephoneNumber 2.5.4.20 S 1;
        otherTelephone 1.2.840.113556.1.2.18 S; homePhone 0.9.2342.19200300.100.1.20 S 1; otherHomePhone 1.2.840.113556.1.2.277 S;
        mobile 0.9.2342.19200300.100.1.41 S 1; otherMobile 1.2.840.113556.1.4.647 S; pager 0.9.2342.19200300.100.1.42 S 1;
        otherPager 1.2.840.113556.1.2.118 S; facsimileTelephoneNumber 2.5.4.23 S 1; otherFacsimileTelephoneNumber 1.2.840.113556.1.4.646 S;
        ipPhone 1.2.840.113556.1.4.721 S 1; otherIpPhone 1.2.840.113556.1.4.722 S; wWWHomePage 1.2.840.113556.1.2.464 S 1; url 1.2.840.113556.1.4.749 S;
        info 1.2.840.113556.1.2.81 S 1; comment 1.2.840.113556.1.4.156 S 1; thumbnailPhoto 2.16.840.1.113730.3.1.35 O 1;
        jpegPhoto 0.9.2342.19200300.100.1.60 O; photo 0.9.2342.19200300.100.1.7 O; preferredLanguage 2.16.840.1.113730.3.1.39 S 1;
        carLicense 2.16.840.1.113730.3.1.1 S; departmentNumber 2.16.840.1.113730.3.1.2 S; uid 0.9.2342.19200300.100.1.1 S; o 2.5.4.10 S; ou 2.5.4.11 S;
        dc 0.9.2342.19200300.100.1.25 S 1; member 2.5.4.31 DN; groupType 1.2.840.113556.1.4.750 I 1; managedBy 1.2.840.113556.1.4.653 DN 1;
        managedObjects 1.2.840.113556.1.4.654 DN; dNSHostName 1.2.840.113556.1.4.619 S 1; operatingSystem 1.2.840.113556.1.4.363 S 1;
        operatingSystemVersion 1.2.840.113556.1.4.364 S 1; operatingSystemServicePack 1.2.840.113556.1.4.365 S 1; location 1.2.840.113556.1.4.222 S 1;
        msDS-AllowedToDelegateTo 1.2.840.113556.1.4.1787 S; gPLink 1.2.840.113556.1.4.891 S 1; gPOptions 1.2.840.113556.1.4.892 I 1;
        minPwdLength 1.2.840.113556.1.4.79 I 1; maxPwdAge 1.2.840.113556.1.4.74 I8 1; minPwdAge 1.2.840.113556.1.4.78 I8 1;
        pwdHistoryLength 1.2.840.113556.1.4.95 I 1; pwdProperties 1.2.840.113556.1.4.93 I 1; lockoutThreshold 1.2.840.113556.1.4.73 I 1;
        lockoutDuration 1.2.840.113556.1.4.60 I8 1; lockOutObservationWindow 1.2.840.113556.1.4.61 I8 1;
        ms-DS-MachineAccountQuota 1.2.840.113556.1.4.1411 I 1; wellKnownObjects 1.2.840.113556.1.4.618 DNB;
        otherWellKnownObjects 1.2.840.113556.1.4.1359 DNB; fSMORoleOwner 1.2.840.113556.1.4.369 DN 1; objectVersion 1.2.840.113556.1.2.76 I 1;
        uidNumber 1.3.6.1.1.1.1.0 I 1; gidNumber 1.3.6.1.1.1.1.1 I 1; unixHomeDirectory 1.3.6.1.1.1.1.3 IA5 1; loginShell 1.3.6.1.1.1.1.4 IA5 1;
        gecos 1.3.6.1.1.1.1.2 IA5 1; memberUid 1.3.6.1.1.1.1.12 IA5; unixUserPassword 1.2.840.113556.1.4.1910 O; seeAlso 2.5.4.34 DN;
        uniqueMember 2.5.4.50 DN; secretary 0.9.2342.19200300.100.1.21 DN; assistant 1.2.840.113556.1.4.652 DN 1; labeledURI 1.3.6.1.4.1.250.1.57 S;
        userSMIMECertificate 2.16.840.1.113730.3.140 O; userPKCS12 2.16.840.1.113730.3.1.216 O; x500uniqueIdentifier 2.5.4.45 O; houseIdentifier 2.5.4.51 S;
        homePostalAddress 1.2.840.113556.1.2.617 S 1; postalAddress 2.5.4.16 S; registeredAddress 2.5.4.26 O; telexNumber 2.5.4.21 O;
        internationalISDNNumber 2.5.4.25 NUM; preferredDeliveryMethod 2.5.4.28 I; businessCategory 2.5.4.15 S; lastKnownParent 1.2.840.113556.1.4.781 DN 1;
        msDS-LastKnownRDN 1.2.840.113556.1.4.2067 S 1; mS-DS-ConsistencyGuid 1.2.840.113556.1.4.1360 O 1; userSharedFolder 1.2.840.113556.1.4.751 S 1;
        serialNumber 2.5.4.5 PR; owner 2.5.4.32 DN 1; roleOccupant 2.5.4.33 DN; nETBIOSName 1.2.840.113556.1.4.87 S 1; dnsRoot 1.2.840.113556.1.4.28 S;
        nCName 1.2.840.113556.1.2.16 DN 1; msDS-Behavior-Version 1.2.840.113556.1.4.1459 I 1; isMemberOfPartialAttributeSet 1.2.840.113556.1.4.639 B 1;
        attributeTypes 2.5.21.5 S; objectClasses 2.5.21.6 S; dITContentRules 2.5.21.2 S; extendedAttributeInfo 1.2.840.113556.1.4.909 S;
        extendedClassInfo 1.2.840.113556.1.4.908 S; allowedAttributes 1.2.840.113556.1.4.913 OID; allowedChildClasses 1.2.840.113556.1.4.911 OID;
        possibleInferiors 1.2.840.113556.1.4.915 OID; structuralObjectClass 2.5.21.9 OID; msDS-ResultantPSO 1.2.840.113556.1.4.2022 DN 1;
        msDS-PSOApplied 1.2.840.113556.1.4.2021 DN; msDS-LockoutThreshold 1.2.840.113556.1.4.2019 I 1;
        msDS-MinimumPasswordLength 1.2.840.113556.1.4.2013 I 1; msDS-MaximumPasswordAge 1.2.840.113556.1.4.2011 I8 1;
        msDS-PasswordSettingsPrecedence 1.2.840.113556.1.4.2023 I 1;
        """;

    // Exchange attributes found in most real domains. They are not part of the base schema, so they are
    // published with a placeholder id.
    private static readonly string[] ExchangeAttributes =
        ["mailNickname", "targetAddress", .. Enumerable.Range(1, 15).Select(n => "extensionAttribute" + n)];

    // What a standards-based directory (RFC 4512, 4519, 4524, 2798, 2307, the password policy draft) defines
    // differently from Active Directory, or defines and Active Directory does not. "op" marks operational attributes,
    // "opw" operational attributes a client may write.
    private const string StandardAttributes = """
        name 2.5.4.41 S; displayName 2.16.840.1.113730.3.1.241 S 1; employeeNumber 2.16.840.1.113730.3.1.3 S 1;
        employeeType 2.16.840.1.113730.3.1.4 S; homeDirectory 1.3.6.1.1.1.1.3 IA5 1; mail 0.9.2342.19200300.100.1.3 IA5;
        dc 0.9.2342.19200300.100.1.25 IA5 1; c 2.5.4.6 S 1; preferredLanguage 2.16.840.1.113730.3.1.39 S 1;
        uidNumber 1.3.6.1.1.1.1.0 I 1; gidNumber 1.3.6.1.1.1.1.1 I 1; loginShell 1.3.6.1.1.1.1.4 IA5 1; gecos 1.3.6.1.1.1.1.2 IA5 1;
        shadowLastChange 1.3.6.1.1.1.1.5 I 1; shadowMin 1.3.6.1.1.1.1.6 I 1; shadowMax 1.3.6.1.1.1.1.7 I 1;
        shadowWarning 1.3.6.1.1.1.1.8 I 1; shadowInactive 1.3.6.1.1.1.1.9 I 1; shadowExpire 1.3.6.1.1.1.1.10 I 1;
        memberOf 1.2.840.113556.1.2.102 DN 0 op; entryUUID 1.3.6.1.1.16.4 S 1 op; entryDN 1.3.6.1.1.20 DN 1 op;
        hasSubordinates 2.5.18.9 B 1 op; createTimestamp 2.5.18.1 T 1 op; modifyTimestamp 2.5.18.2 T 1 op;
        creatorsName 2.5.18.3 DN 1 op; modifiersName 2.5.18.4 DN 1 op; subschemaSubentry 2.5.18.10 DN 1 op;
        structuralObjectClass 2.5.21.9 OID 1 op; pwdChangedTime 1.3.6.1.4.1.42.2.27.8.1.16 T 1 op;
        pwdAccountLockedTime 1.3.6.1.4.1.42.2.27.8.1.17 T 1 op; pwdFailureTime 1.3.6.1.4.1.42.2.27.8.1.19 T 0 op;
        attributeTypes 2.5.21.5 S 0 opw; objectClasses 2.5.21.6 S 0 opw;
        ref 2.16.840.1.113730.3.1.34 S 0 opw;
        """;

    // name, id, superior, kind.
    private const string ActiveDirectoryClasses = """
        top 2.5.6.0 - ABSTRACT; person 2.5.6.6 top STRUCTURAL; organizationalPerson 2.5.6.7 person STRUCTURAL;
        user 1.2.840.113556.1.5.9 organizationalPerson STRUCTURAL; computer 1.2.840.113556.1.3.30 user STRUCTURAL;
        inetOrgPerson 2.16.840.1.113730.3.2.2 user STRUCTURAL; contact 1.2.840.113556.1.5.15 organizationalPerson STRUCTURAL;
        group 1.2.840.113556.1.5.8 top STRUCTURAL; container 1.2.840.113556.1.3.23 top STRUCTURAL;
        organizationalUnit 2.5.6.5 top STRUCTURAL; domain 1.2.840.113556.1.5.66 top ABSTRACT;
        domainDNS 1.2.840.113556.1.5.67 domain STRUCTURAL; builtinDomain 1.2.840.113556.1.5.4 top STRUCTURAL;
        foreignSecurityPrincipal 1.2.840.113556.1.5.76 top STRUCTURAL; msDS-ManagedServiceAccount 1.2.840.113556.1.5.264 computer STRUCTURAL;
        groupPolicyContainer 1.2.840.113556.1.5.157 container STRUCTURAL; msDS-PasswordSettings 1.2.840.113556.1.5.255 top STRUCTURAL;
        msDS-PasswordSettingsContainer 1.2.840.113556.1.5.256 top STRUCTURAL; lostAndFound 1.2.840.113556.1.5.139 top STRUCTURAL;
        configuration 1.2.840.113556.1.5.12 top STRUCTURAL; dMD 1.2.840.113556.1.3.9 top STRUCTURAL;
        classSchema 1.2.840.113556.1.3.13 top STRUCTURAL; attributeSchema 1.2.840.113556.1.3.14 top STRUCTURAL;
        subSchema 2.5.20.1 top STRUCTURAL; securityPrincipal 1.2.840.113556.1.5.6 top AUXILIARY;
        mailRecipient 1.2.840.113556.1.3.46 top AUXILIARY; groupOfNames 2.5.6.9 top STRUCTURAL;
        groupOfUniqueNames 2.5.6.17 top STRUCTURAL; organization 2.5.6.4 top STRUCTURAL; country 2.5.6.2 top STRUCTURAL;
        locality 2.5.6.3 top STRUCTURAL; organizationalRole 2.5.6.8 top STRUCTURAL; device 2.5.6.14 top STRUCTURAL;
        applicationProcess 2.5.6.11 top STRUCTURAL; account 0.9.2342.19200300.100.4.5 top STRUCTURAL;
        simpleSecurityObject 0.9.2342.19200300.100.4.19 top AUXILIARY; posixAccount 1.3.6.1.1.1.2.0 top AUXILIARY;
        shadowAccount 1.3.6.1.1.1.2.1 top AUXILIARY; posixGroup 1.3.6.1.1.1.2.2 top AUXILIARY;
        """;

    private const string StandardClasses = """
        top 2.5.6.0 - ABSTRACT; person 2.5.6.6 top STRUCTURAL; organizationalPerson 2.5.6.7 person STRUCTURAL;
        inetOrgPerson 2.16.840.1.113730.3.2.2 organizationalPerson STRUCTURAL; residentialPerson 2.5.6.10 person STRUCTURAL;
        groupOfNames 2.5.6.9 top STRUCTURAL; groupOfUniqueNames 2.5.6.17 top STRUCTURAL; organizationalUnit 2.5.6.5 top STRUCTURAL;
        organization 2.5.6.4 top STRUCTURAL; organizationalRole 2.5.6.8 top STRUCTURAL; country 2.5.6.2 top STRUCTURAL;
        locality 2.5.6.3 top STRUCTURAL; device 2.5.6.14 top STRUCTURAL; applicationProcess 2.5.6.11 top STRUCTURAL;
        domain 0.9.2342.19200300.100.4.13 top STRUCTURAL; account 0.9.2342.19200300.100.4.5 top STRUCTURAL;
        simpleSecurityObject 0.9.2342.19200300.100.4.19 top AUXILIARY; dcObject 1.3.6.1.4.1.1466.344 top AUXILIARY;
        extensibleObject 1.3.6.1.4.1.1466.101.120.111 top AUXILIARY; subschema 2.5.20.1 top AUXILIARY;
        posixAccount 1.3.6.1.1.1.2.0 top AUXILIARY; shadowAccount 1.3.6.1.1.1.2.1 top AUXILIARY; posixGroup 1.3.6.1.1.1.2.2 top AUXILIARY;
        referral 2.16.840.1.113730.3.2.6 top STRUCTURAL;
        """;

    private static readonly IReadOnlyList<AttributeType> ActiveDirectory = BuildActiveDirectory();
    private static readonly IReadOnlyList<AttributeType> Standard = BuildStandard();
    private static readonly Dictionary<string, AttributeType> ActiveDirectoryByName = Index(ActiveDirectory);
    private static readonly Dictionary<string, AttributeType> StandardByName = Index(Standard);
    private static readonly Dictionary<string, AttributeType> ActiveDirectoryBorrowed = Index(ActiveDirectory.Select(Borrowed));
    private static readonly Dictionary<string, AttributeType> StandardBorrowed = Index(Standard.Select(Borrowed));
    private static readonly IReadOnlyList<ObjectClassType> ActiveDirectoryClassList = ParseClasses(ActiveDirectoryClasses);
    private static readonly IReadOnlyList<ObjectClassType> StandardClassList = ParseClasses(StandardClasses);

    /// <summary>The attribute types a directory of this flavour publishes whatever its data.</summary>
    public static IReadOnlyList<AttributeType> Attributes(bool activeDirectory) => activeDirectory ? ActiveDirectory : Standard;

    public static IReadOnlyList<ObjectClassType> Classes(bool activeDirectory) => activeDirectory ? ActiveDirectoryClassList : StandardClassList;

    /// <summary>
    /// Looks a name up in this flavour's list first, then in the other one: imported data mixes them. From the
    /// other flavour come the id and the syntax only. Whether an attribute is operational is the flavour's own
    /// business: entryUUID is a plain stored attribute to Active Directory.
    /// </summary>
    public static AttributeType? Find(string name, bool activeDirectory)
    {
        var (own, borrowed) = activeDirectory ? (ActiveDirectoryByName, StandardBorrowed) : (StandardByName, ActiveDirectoryBorrowed);
        return own.GetValueOrDefault(name) ?? borrowed.GetValueOrDefault(name);
    }

    public static ObjectClassType? FindClass(string name, bool activeDirectory)
    {
        var (first, second) = activeDirectory ? (ActiveDirectoryClassList, StandardClassList) : (StandardClassList, ActiveDirectoryClassList);
        return first.Concat(second).FirstOrDefault(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The id an attribute or class gets when nothing is known about it but its name.</summary>
    public static string PlaceholderOid(string name) => name + "-oid";

    /// <summary>Names the schema can carry (RFC 4512 "descr"): a letter, then letters, digits or hyphens.</summary>
    public static bool IsValidName(string name) =>
        name.Length is > 0 and <= 255 && char.IsAsciiLetter(name[0]) && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');

    /// <summary>The syntax as an LDAP syntax id. A standards-based directory has no word for Active Directory's own syntaxes.</summary>
    public static string SyntaxOid(AttributeSyntax syntax, bool activeDirectory) => syntax switch
    {
        AttributeSyntax.DistinguishedName => "1.3.6.1.4.1.1466.115.121.1.12",
        AttributeSyntax.Integer => "1.3.6.1.4.1.1466.115.121.1.27",
        AttributeSyntax.LargeInteger => activeDirectory ? "1.2.840.113556.1.4.906" : "1.3.6.1.4.1.1466.115.121.1.27",
        AttributeSyntax.Boolean => "1.3.6.1.4.1.1466.115.121.1.7",
        AttributeSyntax.GeneralizedTime => "1.3.6.1.4.1.1466.115.121.1.24",
        AttributeSyntax.UtcTime => "1.3.6.1.4.1.1466.115.121.1.53",
        AttributeSyntax.OctetString => "1.3.6.1.4.1.1466.115.121.1.40",
        AttributeSyntax.Oid => "1.3.6.1.4.1.1466.115.121.1.38",
        AttributeSyntax.IA5String => "1.3.6.1.4.1.1466.115.121.1.26",
        AttributeSyntax.PrintableString => "1.3.6.1.4.1.1466.115.121.1.44",
        AttributeSyntax.NumericString => "1.3.6.1.4.1.1466.115.121.1.36",
        AttributeSyntax.CaseIgnoreString => activeDirectory ? "1.2.840.113556.1.4.905" : "1.3.6.1.4.1.1466.115.121.1.15",
        AttributeSyntax.CaseExactString => activeDirectory ? "1.2.840.113556.1.4.1362" : "1.3.6.1.4.1.1466.115.121.1.15",
        AttributeSyntax.SecurityDescriptor => activeDirectory ? "1.2.840.113556.1.4.907" : "1.3.6.1.4.1.1466.115.121.1.40",
        AttributeSyntax.DnWithBinary => activeDirectory ? "1.2.840.113556.1.4.903" : "1.3.6.1.4.1.1466.115.121.1.15",
        AttributeSyntax.DnWithString => activeDirectory ? "1.2.840.113556.1.4.904" : "1.3.6.1.4.1.1466.115.121.1.15",
        _ => "1.3.6.1.4.1.1466.115.121.1.15",
    };

    private static List<AttributeType> BuildActiveDirectory()
    {
        var result = ParseAttributes(ActiveDirectoryAttributes);
        result.AddRange(ExchangeAttributes.Select(name => new AttributeType(name, PlaceholderOid(name), AttributeSyntax.DirectoryString, true)));
        return result;
    }

    /// <summary>
    /// The standard list: what Active Directory took over from the standards, with the corrections above on top.
    /// Active Directory made most of these attributes single-valued; the standards did not.
    /// </summary>
    private static List<AttributeType> BuildStandard()
    {
        var corrections = ParseAttributes(StandardAttributes);
        var ownIds = corrections.Select(a => a.Oid).ToHashSet();
        var ownNames = corrections.Select(a => a.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var inherited = ParseAttributes(ActiveDirectoryAttributes)
            .Where(a => !a.Oid.StartsWith(MicrosoftArc, StringComparison.Ordinal) && !ownNames.Contains(a.Name) && !ownIds.Contains(a.Oid))
            .Select(a => a with { SingleValued = false });
        return [.. inherited, .. corrections];
    }

    private static List<AttributeType> ParseAttributes(string table) => Rows(table).Select(row => new AttributeType(
        row[0],
        row[1],
        row[2] switch
        {
            "S" => AttributeSyntax.DirectoryString,
            "DN" => AttributeSyntax.DistinguishedName,
            "I" => AttributeSyntax.Integer,
            "I8" => AttributeSyntax.LargeInteger,
            "B" => AttributeSyntax.Boolean,
            "T" => AttributeSyntax.GeneralizedTime,
            "O" => AttributeSyntax.OctetString,
            "OID" => AttributeSyntax.Oid,
            "IA5" => AttributeSyntax.IA5String,
            "PR" => AttributeSyntax.PrintableString,
            "NUM" => AttributeSyntax.NumericString,
            "CI" => AttributeSyntax.CaseIgnoreString,
            "SD" => AttributeSyntax.SecurityDescriptor,
            "DNB" => AttributeSyntax.DnWithBinary,
            _ => throw new InvalidOperationException($"Unknown syntax code '{row[2]}' for {row[0]}."),
        },
        SingleValued: row.Length > 3 && row[3] == "1",
        Operational: row.Length > 4 && row[4] is "op" or "opw",
        UserModifiable: row.Length > 4 && row[4] == "opw")).ToList();

    private static List<ObjectClassType> ParseClasses(string table) =>
        Rows(table).Select(row => new ObjectClassType(row[0], row[1], row[2] == "-" ? null : row[2], row[3])).ToList();

    private static IEnumerable<string[]> Rows(string table) =>
        table.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(row => row.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static AttributeType Borrowed(AttributeType attribute) => attribute with { Operational = false, UserModifiable = false };

    private static Dictionary<string, AttributeType> Index(IEnumerable<AttributeType> attributes)
    {
        var index = new Dictionary<string, AttributeType>(StringComparer.OrdinalIgnoreCase);
        foreach (var attribute in attributes) index.TryAdd(attribute.Name, attribute);
        return index;
    }
}
