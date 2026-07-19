using System.Diagnostics.CodeAnalysis;
using Konscious.Security.Cryptography;

namespace Rumrunner0.BackToReality.PasswordHashing.Argon2;

/// <summary>Configuration of <see cref="Argon2id" /> hashing.</summary>
/// <param name="Memory">The memory cost in KiB.</param>
/// <param name="Iterations">The iteration count (time cost).</param>
/// <param name="Lanes">The number of parallel lanes/threads.</param>
public sealed record class Argon2IdConfiguration(int Memory, int Iterations, int Lanes)
{
	/// <summary>Parameter separator.</summary>
	internal const string PARAMETER_SEPARATOR = ",";

	/// <summary>Configuration parameter key-value separator.</summary>
	internal const string PARAMETER_KV_SEPARATOR = "=";

	/// <summary>Memory key.</summary>
	internal const string MEMORY_KEY = "m";

	/// <summary>Memory prefix.</summary>
	internal const string MEMORY_PREFIX = $"{MEMORY_KEY}{PARAMETER_KV_SEPARATOR}";

	/// <summary>Iterations key.</summary>
	internal const string ITERATIONS_KEY = "t";

	/// <summary>Iterations prefix.</summary>
	internal const string ITERATION_PREFIX = $"{ITERATIONS_KEY}{PARAMETER_KV_SEPARATOR}";

	/// <summary>Lanes key.</summary>
	internal const string LANES_KEY = "p";

	/// <summary>Lanes prefix.</summary>
	internal const string LANES_PREFIX = $"{LANES_KEY}{PARAMETER_KV_SEPARATOR}";

	/// <summary>Minimum memory cost per lane in KiB (the Argon2 spec requires m ≥ 8p).</summary>
	internal const int MIN_MEMORY_PER_LANE = 8;

	/// <summary>Maximum memory cost in KiB (8 GiB).</summary>
	/// <remarks>
	/// The upper bounds are far above any realistic password hashing configuration.
	/// They exist so that a hash string from an untrusted source can't turn verification into a denial of service.
	/// </remarks>
	internal const int MAX_MEMORY = 8 * 1024 * 1024;

	/// <summary>Minimum iteration count.</summary>
	internal const int MIN_ITERATIONS = 1;

	/// <summary>Maximum iteration count.</summary>
	/// <remarks>See <see cref="MAX_MEMORY" /> remarks.</remarks>
	internal const int MAX_ITERATIONS = 64;

	/// <summary>Minimum number of lanes.</summary>
	internal const int MIN_LANES = 1;

	/// <summary>Maximum number of lanes.</summary>
	/// <remarks>See <see cref="MAX_MEMORY" /> remarks.</remarks>
	internal const int MAX_LANES = 64;

	/// <summary>Flag that indicates whether this configuration is within the supported bounds.</summary>
	internal bool IsValid =>
		Lanes is >= MIN_LANES and <= MAX_LANES &&
		Iterations is >= MIN_ITERATIONS and <= MAX_ITERATIONS &&
		Memory >= Lanes * MIN_MEMORY_PER_LANE && Memory <= MAX_MEMORY;

	/// <summary>Configuration defined in RFC 9106 as FIRST RECOMMENDED.</summary>
	/// <remarks>Safe and high-strength default using 1 iteration, 4 lanes, and 2 GiB of RAM.</remarks>
	public static readonly Argon2IdConfiguration FirstRecommended = new
	(
		Memory: 2048 * 1024,
		Iterations: 1,
		Lanes: 4
	);

	/// <summary>Configuration defined in RFC 9106 as SECOND RECOMMENDED.</summary>
	/// <remarks>Memory-conservative variant using 3 iterations, 4 lanes, and 64 MiB of RAM.</remarks>
	public static readonly Argon2IdConfiguration SecondRecommended = new
	(
		Memory: 64 * 1024,
		Iterations: 3,
		Lanes: 4
	);

	/// <summary>Tries to parse a <see cref="Argon2IdConfiguration" />.</summary>
	/// <param name="source">The source string.</param>
	/// <param name="configuration">The resulting <see cref="Argon2IdConfiguration" />.</param>
	/// <returns><c>true</c> if the configuration was parsed and is within the supported bounds; <c>false</c> otherwise.</returns>
	public static bool TryParse(string? source, [NotNullWhen(true)] out Argon2IdConfiguration? configuration)
	{
		configuration = null;

		if (source is null) return false;
		if (source.Split(PARAMETER_SEPARATOR) is not [var memory, var iteration, var lanes]) return false;

		if (!Argon2ParameterValidator.ValidateInt(memory, MEMORY_PREFIX, out var memoryValue)) return false;
		if (!Argon2ParameterValidator.ValidateInt(iteration, ITERATION_PREFIX, out var iterationValue)) return false;
		if (!Argon2ParameterValidator.ValidateInt(lanes, LANES_PREFIX, out var lanesValue)) return false;

		var candidate = new Argon2IdConfiguration(memoryValue, iterationValue, lanesValue);
		if (!candidate.IsValid) return false;

		configuration = candidate;
		return true;
	}
}