using System;
using System.Diagnostics;
using Rumrunner0.BackToReality.PasswordHashing.Argon2;
using Xunit;

namespace Rumrunner0.BackToReality.PasswordHashing.Tests.Argon2;

/// <summary>Tests for <see cref="Argon2IdPasswordHasher" />.</summary>
public sealed class Argon2IdPasswordHasherTests
{
	/// <summary>Configuration that is far too weak for production but keeps the suite fast.</summary>
	private static readonly Argon2IdConfiguration _fastConfiguration = new (Memory: 8 * 1024, Iterations: 1, Lanes: 1);

	/// <summary>Hash of <c>p@ssw0rd</c> under <see cref="_fastConfiguration" />, computed once for the read-only tests.</summary>
	private static readonly string _validHash = Argon2IdPasswordHasher.Hash("p@ssw0rd", configuration: _fastConfiguration);

	/// <summary>Hash of <c>p@ssw0rd</c> produced by the reference implementation (the <c>argon2</c> CLI with the salt <c>interopsalt16byte</c>).</summary>
	private const string _REFERENCE_IMPLEMENTATION_HASH = "$argon2id$v=19$m=8192,t=3,p=2$aW50ZXJvcHNhbHQxNmJ5dGU$HUQp5yj9NpRFCxLpTZJOjOP9PNlQalaIZ8ShwiHp9uI";

	#region Hashing

	/// <summary>Ensures that a produced hash follows the PHC string format.</summary>
	[Fact]
	public void Hash_ProducesPhcCompliantString()
	{
		Assert.StartsWith("$argon2id$v=19$m=8192,t=1,p=1$", _validHash, StringComparison.Ordinal);

		// A PHC string starts with the separator, so the first segment is empty.
		var segments = _validHash.Split('$');
		Assert.Equal(6, segments.Length);
		Assert.Equal("", segments[0]);

		// Salt and tag are PHC B64: a 16-byte salt is 22 characters, a 32-byte tag is 43, and neither is padded.
		Assert.Equal(22, segments[4].Length);
		Assert.Equal(43, segments[5].Length);
		Assert.DoesNotContain('=', segments[4]);
		Assert.DoesNotContain('=', segments[5]);
	}

	/// <summary>Ensures that the same password produces a unique hash every time.</summary>
	[Fact]
	public void Hash_SamePassword_ProducesUniqueHashes()
	{
		Assert.NotEqual(_validHash, Argon2IdPasswordHasher.Hash("p@ssw0rd", configuration: _fastConfiguration));
	}

	/// <summary>Ensures that the default configuration is <see cref="Argon2IdConfiguration.SecondRecommended" />.</summary>
	[Fact]
	public void Hash_WithoutConfiguration_UsesSecondRecommended()
	{
		Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=4$", Argon2IdPasswordHasher.Hash("p@ssw0rd"), StringComparison.Ordinal);
	}

	/// <summary>Ensures that a configuration outside the supported bounds is rejected.</summary>
	[Fact]
	public void Hash_WithInvalidConfiguration_Throws()
	{
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Hash("p@ssw0rd", configuration: new (Memory: 65536, Iterations: 0, Lanes: 4)));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Hash("p@ssw0rd", configuration: new (Memory: 8, Iterations: 1, Lanes: 4)));
	}

	/// <summary>Ensures that invalid arguments are rejected.</summary>
	[Fact]
	public void Hash_WithInvalidArguments_Throws()
	{
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Hash(null!));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Hash(""));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Hash("p@ssw0rd", pepper: ""));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Hash("p@ssw0rd", associatedData: ""));
	}

	#endregion

	#region Verification

	/// <summary>Ensures that the correct password verifies.</summary>
	[Fact]
	public void Verify_CorrectPassword_ReturnsTrue()
	{
		Assert.True(Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash));
	}

	/// <summary>Ensures that a wrong password does not verify.</summary>
	[Fact]
	public void Verify_WrongPassword_ReturnsFalse()
	{
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd!", _validHash));
	}

	/// <summary>Ensures that the pepper and the associated data must match the values used during hashing.</summary>
	[Fact]
	public void Verify_PepperAndAssociatedData_MustMatch()
	{
		var hash = Argon2IdPasswordHasher.Hash("p@ssw0rd", pepper: "app-secret", associatedData: "user-42", configuration: _fastConfiguration);

		Assert.True(Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-42"));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, associatedData: "user-42"));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "other-secret", associatedData: "user-42"));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", hash, pepper: "app-secret", associatedData: "user-1"));
	}

	/// <summary>Ensures that a hash produced by the reference implementation verifies.</summary>
	[Fact]
	public void Verify_ReferenceImplementationHash_ReturnsTrue()
	{
		Assert.True(Argon2IdPasswordHasher.Verify("p@ssw0rd", _REFERENCE_IMPLEMENTATION_HASH));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd!", _REFERENCE_IMPLEMENTATION_HASH));
	}

	/// <summary>Ensures that invalid arguments are rejected.</summary>
	[Fact]
	public void Verify_WithInvalidArguments_Throws()
	{
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Verify(null!, _validHash));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Verify("", _validHash));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Verify("p@ssw0rd", null!));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Verify("p@ssw0rd", ""));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Verify("p@ssw0rd", "   "));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash, pepper: ""));
		Assert.ThrowsAny<ArgumentException>(() => Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash, associatedData: ""));
	}

	#endregion

	#region Rejection

	/// <summary>Ensures that a malformed hash is rejected instead of throwing.</summary>
	[Fact]
	public void Verify_MalformedHash_ReturnsFalse()
	{
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", "definitely not a hash"));

		// Structural damage to a valid hash.
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash[1..]));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", $"${_validHash}"));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", $"{_validHash}$x"));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash[.._validHash.LastIndexOf('$')]));
	}

	/// <summary>Ensures that an unsupported algorithm or version is rejected.</summary>
	[Fact]
	public void Verify_UnsupportedAlgorithmOrVersion_ReturnsFalse()
	{
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash.Replace("$argon2id$", "$argon2i$")));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash.Replace("$v=19$", "$v=18$")));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", _validHash.Replace("$v=19$", "$v=x$")));
	}

	/// <summary>Ensures that a salt or tag that is not strict PHC B64 is rejected.</summary>
	[Fact]
	public void Verify_NonStrictBase64_ReturnsFalse()
	{
		var segments = _validHash.Split('$');
		var prefix = $"${segments[1]}${segments[2]}${segments[3]}";

		// Padding is not allowed by PHC B64.
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", $"{prefix}${segments[4]}==${segments[5]}="));

		// Only the standard Base64 alphabet is allowed.
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", $"{prefix}$abc-def0${segments[5]}"));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", $"{prefix}${segments[4][..10]} {segments[4][11..]}${segments[5]}"));
	}

	/// <summary>Ensures that a salt or tag with a wrong length is rejected.</summary>
	[Fact]
	public void Verify_WrongSaltOrTagLength_ReturnsFalse()
	{
		var segments = _validHash.Split('$');
		var prefix = $"${segments[1]}${segments[2]}${segments[3]}";

		// A 4-byte salt is below the spec minimum of 8; a 17-byte tag can never match the fixed 32-byte output.
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", $"{prefix}$dGVzdA${segments[5]}"));
		Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", $"{prefix}${segments[4]}$aW50ZXJvcHNhbHQxNmJ5dGU"));
	}

	/// <summary>Ensures that hostile parameters are rejected quickly instead of turning verification into a denial of service.</summary>
	[Fact]
	public void Verify_HostileParameters_ReturnsFalseFast()
	{
		var hostileHashes = new []
		{
			"$argon2id$v=19$m=2147483647,t=3,p=4$aW50ZXJvcHNhbHQxNmJ5dGU$HUQp5yj9NpRFCxLpTZJOjOP9PNlQalaIZ8ShwiHp9uI",
			"$argon2id$v=19$m=65536,t=2147483647,p=4$aW50ZXJvcHNhbHQxNmJ5dGU$HUQp5yj9NpRFCxLpTZJOjOP9PNlQalaIZ8ShwiHp9uI",
			"$argon2id$v=19$m=65536,t=3,p=2147483647$aW50ZXJvcHNhbHQxNmJ5dGU$HUQp5yj9NpRFCxLpTZJOjOP9PNlQalaIZ8ShwiHp9uI",
			"$argon2id$v=19$m=16,t=3,p=4$aW50ZXJvcHNhbHQxNmJ5dGU$HUQp5yj9NpRFCxLpTZJOjOP9PNlQalaIZ8ShwiHp9uI"
		};

		var stopwatch = Stopwatch.StartNew();
		foreach (var hostileHash in hostileHashes)
		{
			Assert.False(Argon2IdPasswordHasher.Verify("p@ssw0rd", hostileHash));
		}

		// Rejection happens during parsing, long before any memory or CPU is spent.
		Assert.True(stopwatch.ElapsedMilliseconds < 1000);
	}

	#endregion
}