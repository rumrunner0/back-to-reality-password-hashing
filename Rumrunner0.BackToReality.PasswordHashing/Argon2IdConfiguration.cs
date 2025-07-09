using System;
using Konscious.Security.Cryptography;

namespace Rumrunner0.BackToReality.PasswordHashing;

/// <summary>Configuration of <see cref="Argon2id" /> hashing.</summary>
/// <param name="Memory">The memory cost in KiB (64 MiB).</param>
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

	/// <summary>
	/// Configuration defined in RFC 9106 as FIRST RECOMMENDED.
	/// Safe and high-strength default using 1 iteration, 4 lanes, and 2 GiB of RAM.
	/// </summary>
	public static readonly Argon2IdConfiguration FirstRecommended = new
	(
		Memory: 2048 * 1024,
		Iterations: 1,
		Lanes: 4
	);

	/// <summary>
	/// Configuration defined in RFC 9106 as SECOND RECOMMENDED.
	/// Memory-conservative variant using 3 iterations, 4 lanes, and 64 MiB of RAM.
	/// </summary>
	public static readonly Argon2IdConfiguration SecondRecommended = new
	(
		Memory: 64 * 1024,
		Iterations: 3,
		Lanes: 4
	);

	/// <summary>
	/// Tries to parse a <see cref="Argon2IdConfiguration" />.
	/// </summary>
	/// <param name="source">The source string.</param>
	/// <param name="configuration">The resulting <see cref="Argon2IdConfiguration" /> containing parsed configuration.</param>
	/// <returns><c>true</c> if the configuration was parsed; <c>false</c> otherwise.</returns>
	public static bool TryParse(string source, out Argon2IdConfiguration configuration)
	{
		configuration = null!;

		if(source.Split(PARAMETER_SEPARATOR, StringSplitOptions.RemoveEmptyEntries) is not
		[
			var memory,
			var iteration,
			var lanes
		])
		{
			return false;
		}

		if (!Argon2ParameterValidator.ValidateInt(memory, MEMORY_PREFIX, out var memoryValue)) return false;
		if (!Argon2ParameterValidator.ValidateInt(iteration, ITERATION_PREFIX, out var iterationValue)) return false;
		if (!Argon2ParameterValidator.ValidateInt(lanes, LANES_PREFIX, out var lanesValue)) return false;

		configuration = new (memoryValue, iterationValue, lanesValue);
		return true;
	}
}