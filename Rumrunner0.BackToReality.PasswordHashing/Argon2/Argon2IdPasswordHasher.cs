using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Rumrunner0.BackToReality.SharedExtensions.Collections;
using Rumrunner0.BackToReality.SharedExtensions.Exceptions;
using Rumrunner0.BackToReality.SharedExtensions.Extensions;

namespace Rumrunner0.BackToReality.PasswordHashing.Argon2;

/// <summary>Argon2-id password hasher.</summary>
public static class Argon2IdPasswordHasher
{
	/// <summary>Algorithm name.</summary>
	internal const string ALGORITHM_NAME = "argon2id";

	/// <summary>Argon2 version id (19 ≙ spec v1.3).</summary>
	internal const int VERSION = 19;

	/// <summary>Size of the random salt in bytes (128 bits).</summary>
	internal const int SALT_LENGTH = 16;

	/// <summary>Minimum size of a salt accepted during verification in bytes (the Argon2 spec minimum).</summary>
	internal const int MIN_SALT_LENGTH = 8;

	/// <summary>Size of the derived tag in bytes (256 bits).</summary>
	internal const int TAG_LENGTH = 32;

	/// <summary>PHC hash part separator.</summary>
	internal const string HASH_PARTS_SEPARATOR = "$";

	/// <summary>Configuration parameter key-value separator.</summary>
	internal const string PARAMETER_KV_SEPARATOR = "=";

	/// <summary>Version key.</summary>
	internal const string VERSION_KEY = "v";

	/// <summary>Version prefix.</summary>
	internal const string VERSION_PREFIX = $"{VERSION_KEY}{PARAMETER_KV_SEPARATOR}";

	/// <summary>Default configuration.</summary>
	private static readonly Argon2IdConfiguration _defaultConfiguration = Argon2IdConfiguration.SecondRecommended;

	/// <summary>PHC-formatted hash template.</summary>
	/// <remarks>A PHC string starts with the separator: <c>$argon2id$...</c>.</remarks>
	private static readonly string _phcHashTemplate = HASH_PARTS_SEPARATOR + new []
	{
		ALGORITHM_NAME,
		$"{VERSION_PREFIX}{VERSION}",

		new []
		{
			$"{Argon2IdConfiguration.MEMORY_PREFIX}{{0}}",
			$"{Argon2IdConfiguration.ITERATION_PREFIX}{{1}}",
			$"{Argon2IdConfiguration.LANES_PREFIX}{{2}}"
		}
		.StringJoin(Argon2IdConfiguration.PARAMETER_SEPARATOR),

		"{3}", // Salt.
		"{4}"  // Tag.
	}
	.StringJoin(HASH_PARTS_SEPARATOR);

	/// <summary>Generates a PHC-formatted Argon2-id hash for a <paramref name="password" />.</summary>
	/// <param name="password">The plain-text password to hash.</param>
	/// <param name="pepper">The additional secret string (acts as a second factor to harden the hash against precomputed or rainbow table attacks).</param>
	/// <param name="associatedData">The context-specific string (used as associated data in the computation to bind the hash to specific usage).</param>
	/// <param name="configuration">
	/// The configuration. There are 2 predefined configurations recommended to use.
	/// Please see <see cref="Argon2IdConfiguration" />.<see cref="Argon2IdConfiguration.FirstRecommended" />
	/// and <see cref="Argon2IdConfiguration" />.<see cref="Argon2IdConfiguration.SecondRecommended" />.
	/// </param>
	/// <returns>An Argon2-id PHC-compliant hash string.</returns>
	/// <remarks>
	/// Example of a return string: <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;b64-salt&gt;$&lt;b64-tag&gt;</c>.
	/// Salt and tag are encoded as PHC B64: standard Base64 with the trailing padding omitted.
	/// </remarks>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="password" /> is <c>null</c>.</exception>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="password" />, <paramref name="pepper" /> or <paramref name="associatedData" /> is empty,
	/// or <paramref name="configuration" /> is outside the supported bounds (see <see cref="Argon2IdConfiguration" />).
	/// </exception>
	public static string Hash(string password, string? pepper = null, string? associatedData = null, Argon2IdConfiguration? configuration = null)
	{
		ArgumentExceptionExtensions.ThrowIfNullOrEmpty(password);
		ArgumentExceptionExtensions.ThrowIfEmpty(pepper);
		ArgumentExceptionExtensions.ThrowIfEmpty(associatedData);

		configuration ??= _defaultConfiguration;
		if (!configuration.IsValid) ArgumentExceptionExtensions.Throw("The configuration is outside the supported bounds", nameof(configuration));

		var salt = (Span<byte>) stackalloc byte[SALT_LENGTH];
		RandomNumberGenerator.Fill(salt);

		var tag = DeriveTag(password, configuration, salt, pepper, associatedData);

		return string.Format
		(
			_phcHashTemplate,
			configuration.Memory,
			configuration.Iterations,
			configuration.Lanes,
			EncodePhcBase64String(salt),
			EncodePhcBase64String(tag)
		);
	}

	/// <summary>Verifies a <paramref name="password" /> against a PHC-formatted Argon2-id <paramref name="hash" />.</summary>
	/// <param name="password">The plain-text password to verify.</param>
	/// <param name="hash">The Argon2-id PHC-compliant hash string to verify against.</param>
	/// <param name="pepper">The additional secret string that must match the value used during hashing.</param>
	/// <param name="associatedData">The context-specific string that must match the value used during hashing.</param>
	/// <returns><c>true</c> if the <paramref name="password" /> matches the <paramref name="hash" />; <c>false</c> otherwise.</returns>
	/// <remarks>
	/// Returns <c>false</c> (instead of throwing) for a <paramref name="hash" /> that is malformed,
	/// uses an unsupported algorithm or version, or carries parameters outside the supported bounds.
	/// </remarks>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="password" /> or <paramref name="hash" /> is <c>null</c>.</exception>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="password" /> is empty, <paramref name="hash" /> is empty or whitespace,
	/// or <paramref name="pepper" /> or <paramref name="associatedData" /> is empty.
	/// </exception>
	public static bool Verify(string password, string hash, string? pepper = null, string? associatedData = null)
	{
		ArgumentExceptionExtensions.ThrowIfNullOrEmpty(password);
		ArgumentExceptionExtensions.ThrowIfNullOrEmptyOrWhiteSpace(hash);
		ArgumentExceptionExtensions.ThrowIfEmpty(pepper);
		ArgumentExceptionExtensions.ThrowIfEmpty(associatedData);

		if (!TryParseHash(hash, out var configuration, out var hashedSalt, out var hashedTag)) return false;

		var computedTag = DeriveTag(password, configuration, hashedSalt, pepper, associatedData);
		return CryptographicOperations.FixedTimeEquals(computedTag, hashedTag);
	}

	/// <summary>Derives a tag.</summary>
	/// <param name="password">The plain-text password.</param>
	/// <param name="configuration">The configuration.</param>
	/// <param name="salt">The salt.</param>
	/// <param name="pepper">The pepper.</param>
	/// <param name="associatedData">The associated data.</param>
	/// <returns>Derived tag.</returns>
	private static byte[] DeriveTag(string password, Argon2IdConfiguration configuration, ReadOnlySpan<byte> salt, string? pepper = null, string? associatedData = null)
	{
		using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));

		argon2.MemorySize = configuration.Memory;
		argon2.Iterations = configuration.Iterations;
		argon2.DegreeOfParallelism = configuration.Lanes;

		argon2.Salt = salt.ToArray();
		if (!pepper.IsNullOrEmpty()) argon2.KnownSecret = Encoding.UTF8.GetBytes(pepper);
		if (!associatedData.IsNullOrEmpty()) argon2.AssociatedData = Encoding.UTF8.GetBytes(associatedData);

		return argon2.GetBytes(TAG_LENGTH);
	}

	/// <summary>Tries to parse a <paramref name="hash" />.</summary>
	/// <param name="hash">The hash.</param>
	/// <param name="configuration">The resulting parsed configuration.</param>
	/// <param name="salt">The resulting array containing parsed salt.</param>
	/// <param name="tag">The resulting array containing parsed tag.</param>
	/// <returns><c>true</c> if the hash was parsed; <c>false</c> otherwise.</returns>
	private static bool TryParseHash(string hash, [NotNullWhen(true)] out Argon2IdConfiguration? configuration, out byte[] salt, out byte[] tag)
	{
		configuration = null;
		salt = [];
		tag = [];

		// A PHC string starts with the separator, producing an empty first segment.
		// The strict segment count rejects doubled separators and trailing junk.
		if (hash.Split(HASH_PARTS_SEPARATOR) is not
		[
			"",
			var algorithm,
			var version,
			var parameters,
			var saltString,
			var tagString
		])
		{
			return false;
		}

		if (!algorithm.Equals(ALGORITHM_NAME, StringComparison.OrdinalIgnoreCase)) return false;
		if (!Argon2ParameterValidator.ValidateInt(version, VERSION_PREFIX, out var versionValue) || versionValue != VERSION) return false;
		if (!Argon2IdConfiguration.TryParse(parameters, out configuration)) return false;

		// The tag length must match exactly.
		// DeriveTag always produces TAG_LENGTH bytes, so any other length could never verify.
		if (!TryDecodePhcBase64String(saltString, out salt) || salt.Length < MIN_SALT_LENGTH) return false;
		if (!TryDecodePhcBase64String(tagString, out tag) || tag.Length != TAG_LENGTH) return false;

		return true;
	}

	/// <summary>Encodes <paramref name="bytes" /> to a PHC B64 string.</summary>
	/// <param name="bytes">The bytes to encode.</param>
	/// <returns>A PHC B64 string.</returns>
	/// <remarks>PHC B64 is standard Base64 (RFC 4648 §4) with the trailing padding omitted.</remarks>
	private static string EncodePhcBase64String(ReadOnlySpan<byte> bytes)
	{
		return Convert.ToBase64String(bytes).TrimEnd('=');
	}

	/// <summary>Tries to decode a PHC B64 <paramref name="source" />.</summary>
	/// <param name="source">The PHC B64 string to decode.</param>
	/// <param name="bytes">The resulting array containing decoded bytes.</param>
	/// <returns><c>true</c> if the string was decoded; <c>false</c> otherwise.</returns>
	/// <remarks>Only the standard Base64 alphabet is allowed (no whitespace and no padding).</remarks>
	private static bool TryDecodePhcBase64String(string source, out byte[] bytes)
	{
		bytes = [];

		// A length of 4n + 1 is never a valid Base64 sequence.
		if (source.Length == 0 || source.Length % 4 == 1) return false;

		foreach (var c in source)
		{
			if (c is not ((>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '+' or '/')) return false;
		}

		var padding = (4 - source.Length % 4) % 4;
		return StringExtensions.TryGetBytesFromBase64String($"{source}{new string('=', padding)}", out bytes);
	}
}