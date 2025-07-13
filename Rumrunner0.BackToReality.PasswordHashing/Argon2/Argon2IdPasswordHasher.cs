using System;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Rumrunner0.BackToReality.SharedExtensions.Exceptions;
using Rumrunner0.BackToReality.SharedExtensions.Extensions;

namespace Rumrunner0.BackToReality.PasswordHashing.Argon2;

// Argon2-id password hasher, v0.1.0, from Jul 10, 2025.

// TODO: It will be good to track issues in core library :)
// https://github.com/kmaragon/Konscious.Security.Cryptography/issues

/// <summary>Argon2-id password hasher.</summary>
public sealed class Argon2IdPasswordHasher
{
	/// <summary>Algorithm name.</summary>
	internal const string ALGORITHM_NAME = "argon2id";

	/// <summary>Argon2 version id (19 ≙ spec v1.3).</summary>
	internal const int VERSION = 19;

	/// <summary>Size of the random salt in bytes (128 bits).</summary>
	internal const int SALT_LENGTH = 16;

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
	private static readonly string _phcHashTemplate = new []
	{
		ALGORITHM_NAME,
		$"{VERSION_KEY}{PARAMETER_KV_SEPARATOR}{VERSION}",

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

	/// <summary>
	/// Generates a PHC-formatted Argon2-id hash for a <paramref name="password" />.
	/// </summary>
	/// <param name="password">The plain-text password to hash.</param>
	/// <param name="pepper">The additional secret string (acts as a second factor to harden the hash against precomputed or rainbow table attacks).</param>
	/// <param name="associatedData">The context-specific string (used as associated data in the computation to bind the hash to specific usage).</param>
	/// <param name="configuration">
	/// The configuration. There are 2 predefined configurations recommended to use.
	/// Please see <see cref="Argon2IdConfiguration" />.<see cref="Argon2IdConfiguration.FirstRecommended" />
	/// and <see cref="Argon2IdConfiguration" />.<see cref="Argon2IdConfiguration.SecondRecommended" />.
	/// </param>
	/// <returns>An Argon2-id PHC-compliant hash string.</returns>
	/// <remarks>Example of a return string: <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;base64-salt&gt;$&lt;base64-tag&gt;</c>.</remarks>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="password" /> is null.</exception>
	public static string Hash(string password, string? pepper = null, string? associatedData = null, Argon2IdConfiguration? configuration = null)
	{
		ArgumentExceptionExtensions.ThrowIfNullOrEmpty(password);
		ArgumentExceptionExtensions.ThrowIfEmpty(pepper);
		ArgumentExceptionExtensions.ThrowIfEmpty(associatedData);

		configuration ??= _defaultConfiguration;

		var salt = (Span<byte>) stackalloc byte[SALT_LENGTH];
		RandomNumberGenerator.Fill(salt);

		var tag = DeriveTag(password, configuration, salt, pepper, associatedData);

		return string.Format
		(
			_phcHashTemplate,
			configuration.Memory,
			configuration.Iterations,
			configuration.Lanes,
			Convert.ToBase64String(salt),
			Convert.ToBase64String(tag)
		);
	}

	/// <summary>
	/// Verifies a <paramref name="password" /> against a PHC-formatted Argon2-id <paramref name="hash" />.
	/// </summary>
	/// <param name="password">The plain-text password to verify.</param>
	/// <param name="hash">The Argon2-id PHC-compliant hash string to verify against.</param>
	/// <param name="pepper">The additional secret string that must match the value used during hashing.</param>
	/// <param name="associatedData">The context-specific string that must match the value used during hashing.</param>
	/// <returns><c>true</c> if the <paramref name="password" /> matches the <paramref name="hash" />; otherwise; <c>false</c>.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="password" /> or <paramref name="hash" /> is null.</exception>
	public static bool Verify(string password, string hash, string? pepper = null, string? associatedData = null)
	{
		ArgumentExceptionExtensions.ThrowIfNullOrEmpty(password);
		ArgumentExceptionExtensions.ThrowIfNullOrEmptyOrWhiteSpace(hash);
		ArgumentExceptionExtensions.ThrowIfEmpty(pepper);
		ArgumentExceptionExtensions.ThrowIfEmpty(associatedData);

		if (!TryParseHash(hash, out var configuration, out var hashedSalt, out var hashedTag))
		{
			return false;
		}

		var computedTag = DeriveTag(password, configuration, hashedSalt, pepper, associatedData);
		return CryptographicOperations.FixedTimeEquals(computedTag, hashedTag);
	}

	/// <summary>
	/// Derives a tag.
	/// </summary>
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
		if (!pepper.IsNullOrEmpty()) argon2.KnownSecret = Encoding.UTF8.GetBytes(pepper!);
		if (!associatedData.IsNullOrEmpty()) argon2.AssociatedData = Encoding.UTF8.GetBytes(associatedData!);

		return argon2.GetBytes(TAG_LENGTH);
	}

	/// <summary>
	/// Tries to parse a <paramref name="hash" />.
	/// </summary>
	/// <param name="hash">The hash.</param>
	/// <param name="configuration">The configuration.</param>
	/// <param name="salt">The resulting span containing parsed salt.</param>
	/// <param name="tag">The resulting span containing parsed tag.</param>
	/// <returns><c>true</c> if the hash was parsed; <c>false</c> otherwise.</returns>
	private static bool TryParseHash(string hash, out Argon2IdConfiguration configuration, out ReadOnlySpan<byte> salt, out ReadOnlySpan<byte> tag)
	{
		configuration = null!;
		salt = ReadOnlySpan<byte>.Empty;
		tag = ReadOnlySpan<byte>.Empty;

		if (hash.Split(HASH_PARTS_SEPARATOR, StringSplitOptions.RemoveEmptyEntries) is not
		[
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
		if (!StringExtensions.TryGetBytesFromBase64String(saltString, out salt)) return false;
		if (!StringExtensions.TryGetBytesFromBase64String(tagString, out tag)) return false;

		return true;
	}
}