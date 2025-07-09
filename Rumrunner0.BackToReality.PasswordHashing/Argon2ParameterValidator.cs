using System;
using Konscious.Security.Cryptography;

namespace Rumrunner0.BackToReality.PasswordHashing;

/// <summary>Parameter validator for <see cref="Argon2" /> password hasher.</summary>
internal static class Argon2ParameterValidator
{
	/// <summary>Validates a number parameter.</summary>
	/// <param name="parameter">The parameter to validate.</param>
	/// <param name="prefix">The corresponding prefix.</param>
	/// <param name="value">The resulting number containing validated parameter value.</param>
	/// <returns><c>true</c> if the parameter is valid; <c>false</c> otherwise.</returns>
	internal static bool ValidateInt(string parameter, string prefix, out int value)
	{
		if
		(
			// A raw parameter must start with prefix.
			!parameter.StartsWith(prefix, StringComparison.Ordinal) ||

			// Its value must be a valid number.
			!int.TryParse(parameter.AsSpan(start: prefix.Length), out var v) ||

			// Its value must be greater than 0.
			v <= 0
		)
		{
			value = default;
			return false;
		}

		value = v;
		return true;
	}
}